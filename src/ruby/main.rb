require 'json'
require 'jwt'
require 'neo4j_bolt'
require 'sinatra/base'
require 'sinatra/cookies'
require 'mail'

require './credentials.template.rb'
warn_level = $VERBOSE
$VERBOSE = nil
require './credentials.rb'
$VERBOSE = warn_level
DASHBOARD_SERVICE = ENV['DASHBOARD_SERVICE']

Neo4jBolt.bolt_host = 'neo4j'
Neo4jBolt.bolt_port = 7687

def debug(message, index = 0)
    index = 0
    begin
        while index < caller_locations.size - 1 && ['transaction', 'neo4j_query', 'neo4j_query_expect_one'].include?(caller_locations[index].base_label)
            index += 1
        end
    rescue
        index = 0
    end
    l = caller_locations[index]
    ls = ''
    begin
        ls = "#{l.path.sub('/app/', '')}:#{l.lineno} @ #{l.base_label}"
    rescue
        ls = "#{l[0].sub('/app/', '')}:#{l[1]}"
    end
    STDERR.puts "#{DateTime.now.strftime('%H:%M:%S')} [#{ls}] #{message}"
end

def debug_error(message)
    l = caller_locations.first
    ls = ''
    begin
        ls = "#{l.path.sub('/app/', '')}:#{l.lineno} @ #{l.base_label}"
    rescue
        ls = "#{l[0].sub('/app/', '')}:#{l[1]}"
    end
    STDERR.puts "#{DateTime.now.strftime('%H:%M:%S')} [ERROR] [#{ls}] #{message}"
end

def fix_h_to_hh(s)
    return nil if s.nil?
    if s =~ /^\d:\d\d$/
        '0' + s
    else
        s
    end
end

class Neo4jGlobal
    include Neo4jBolt
end

$neo4j = Neo4jGlobal.new

class RandomTag
    BASE_31_ALPHABET = '0123456789bcdfghjklmnpqrstvwxyz'
    def self.to_base31(i)
        result = ''
        while i > 0
            result += BASE_31_ALPHABET[i % 31]
            i /= 31
        end
        result
    end

    def self.generate(length = 12)
        self.to_base31(SecureRandom.hex(length).to_i(16))[0, length]
    end
end

def mail_html_to_plain_text(s)
    s.gsub('<p>', "\n\n").gsub(/<br\s*\/?>/, "\n").gsub(/<\/?[^>]*>/, '').strip
end

def deliver_mail(plain_text = nil, &block)
    mail = Mail.new do
        charset = 'UTF-8'
        message = self.instance_eval(&block)
        if plain_text.nil?
            html_part do
                content_type 'text/html; charset=UTF-8'
                body message
            end

            text_part do
                content_type 'text/plain; charset=UTF-8'
                body mail_html_to_plain_text(message)
            end
        else
            text_part do
                content_type 'text/plain; charset=UTF-8'
                body plain_text
            end
        end
    end
    if DEVELOPMENT
        if DEVELOPMENT_MAIL_DELIVERY_POSITIVE_LIST.include?(mail.to.first)
            debug "Sending mail to #{mail.to.join(' / ')} because first recipient is included in DEVELOPMENT_MAIL_DELIVERY_POSITIVE_LIST..."
            mail.deliver!
        else
            debug "Not sending mail to because we're in development: #{mail.subject} => #{mail.to.join(' / ')}"
            debug mail.to_s
        end
    else
        mail.deliver!
    end
end

def join_with_sep(list, a, b)
    list.size == 1 ? list.first : [list[0, list.size - 1].join(a), list.last].join(b)
end

class SetupDatabase
    include Neo4jBolt

    def setup(main)
        wait_for_neo4j
        delay = 1
        10.times do
            begin
                neo4j_query("MATCH (n) RETURN n LIMIT 1;")
                # break unless ENV['DASHBOARD_SERVICE'] == 'ruby'
                debug "Setting up constraints and indexes..."
                setup_constraints_and_indexes(['LoginCode/tag', 'User/email', 'Entry/sha1'], [])
                neo4j_query("CREATE INDEX BELONGS_TO_timestamp IF NOT EXISTS FOR ()-[r:BELONGS_TO]-() ON (r.timestamp)")
                debug "Setup finished."
                break
            rescue
                debug $!
                debug "Retrying setup after #{delay} seconds..."
                sleep delay
                delay += 1
            end
        end
    end
end

class Main < Sinatra::Base
    include Neo4jBolt
    helpers Sinatra::Cookies

    configure do
        set :show_exceptions, false
    end

    def self.init_cache()
        @@cache = {}
        @@cache[:users] = {}
        @@cache[:entries] = {}
        @@cache[:last_timestamp_for_user] = {}
        @@cache[:latest_version_for_user] = {}
    end

    def self.update_version_for_user(email, version)
        return if @@cache[:latest_version_for_user][email] == version
        old_version_code = (@@cache[:latest_version_for_user][email] || '').split('+')[1].to_i
        new_version_code = version.split('+')[1].to_i
        if new_version_code > old_version_code
            STDERR.puts "UPDATE VERSION: #{email} #{version}"
            $neo4j.neo4j_query(<<~END_OF_QUERY, {:email => email, :version => version})
                MATCH (u:User {email: $email})
                SET u.latest_version = $version;
            END_OF_QUERY
            @@cache[:latest_version_for_user][email] = version
        end
    end

    def self.add_entry_to_cache(email, sha1, t)
        @@cache[:users][email] ||= {}
        @@cache[:users][email][sha1] ||= t
        @@cache[:users][email][sha1] = t if t > @@cache[:users][email][sha1]
        @@cache[:entries][sha1] ||= {}
        @@cache[:entries][sha1][email] ||= t
        @@cache[:entries][sha1][email] = t if t > @@cache[:entries][sha1][email]
        @@cache[:last_timestamp_for_user][email] ||= t
        @@cache[:last_timestamp_for_user][email] = t if t > @@cache[:last_timestamp_for_user][email]
    end

    def self.collect_data
        $neo4j.wait_for_neo4j
        @@user_info = {}
        File.open('invitations.txt') do |f|
            f.each_line do |line|
                line.strip!
                next if line.empty? || line[0] == '#'
                parts = line.split(/\s+/)
                email = parts[0].strip
                nc_login = parts[1].strip
                name = parts[2, parts.size - 2].join(' ').strip
                @@user_info[email] = {
                    :name => name,
                    :nc_login => nc_login
                }
            end
        end
        @@allowed_suffixes = []
        File.open('invitations-suffixes.txt') do |f|
            f.each_line do |line|
                line.strip!
                next if line.empty? || line[0] == '#'
                suffix = line.strip
                raise "Invalid suffix format: #{suffix} (must start with @)" unless suffix[0] == '@'
                @@allowed_suffixes << suffix
            end
        end
        @@user_info['max.mustermann@mail.gymnasiumsteglitz.de'] = {:name => 'Max Mustermann', :nc_login => 'max.mustermann'}
        @@shop = YAML.load(File.read('shop.yaml'))
        @@voc_data = JSON.load(File.read('/repos/agr-app/flutter/data/voc.json'))
        @@sphinx_data = JSON.load(File.read('/repos/agr-app/flutter/data/sphinx-haul.json'))
        STDERR.puts "Voc: #{@@voc_data['words'].size}"
        STDERR.puts "Sphinx forms: #{@@sphinx_data['forms'].size}"
        self.init_cache()
        @@cache[:users] ||= {}
        results = $neo4j.neo4j_query(<<~END_OF_QUERY).map { |x| {:email => x['email'], :latest_version => x['latest_version']} }
            MATCH (u:User) RETURN u.email AS email, u.latest_version AS latest_version;
        END_OF_QUERY
        count = 0
        results.each do |row|
            email = row[:email]
            rows = $neo4j.neo4j_query(<<~END_OF_QUERY, {:email => email}).each do |row|
                MATCH (e:Entry)-[r:BELONGS_TO]->(u:User {email: $email}) RETURN r.timestamp AS t, e.sha1 AS sha1;
            END_OF_QUERY
                count += 1
                t = row['t']
                sha1 = row['sha1']
                self.add_entry_to_cache(email, sha1, t)
            end
            latest_version = row[:latest_version]
            @@cache[:latest_version_for_user][email] = latest_version if latest_version
        end
        STDERR.puts "Finished loading #{count} events from #{results.size} users."
    end

    configure do
        self.collect_data() unless defined?(SKIP_COLLECT_DATA) && SKIP_COLLECT_DATA
        if ENV['SERVICE'] == 'ruby'
            setup = SetupDatabase.new()
            setup.setup(self)
        end
        if ['thin', 'rackup'].include?(File.basename($0))
            debug('Server is up and running!')
        end
        if ENV['SERVICE'] == 'ruby' && File.basename($0) == 'pry.rb'
            binding.pry
        end
    end

    def assert(condition, message = 'assertion failed', suppress_backtrace = false, delay = nil)
        unless condition
            debug_error message
            e = StandardError.new(message)
            e.set_backtrace([]) if suppress_backtrace
            sleep delay unless delay.nil?
            raise e
        end
    end

    def assert_with_delay(condition, message = 'assertion failed', suppress_backtrace = false)
        assert(condition, message, suppress_backtrace, 3.0)
    end

    def test_request_parameter(data, key, options)
        type = ((options[:types] || {})[key]) || String
        assert(data[key.to_s].is_a?(type), "#{key.to_s} is a #{type}")
        if type == String
            assert(data[key.to_s].size <= (options[:max_value_lengths][key] || options[:max_string_length]), 'too_much_data')
        end
    end

    def parse_request_data(options = {})
        options[:max_body_length] ||= 512
        options[:max_string_length] ||= 512
        options[:required_keys] ||= []
        options[:optional_keys] ||= []
        options[:max_value_lengths] ||= {}
        data_str = request.body.read(options[:max_body_length]).to_s
#         debug data_str
        @latest_request_body = data_str.dup
        begin
            assert(data_str.is_a? String)
            assert(data_str.size < options[:max_body_length], 'too_much_data')
            data = JSON::parse(data_str)
            @latest_request_body_parsed = data.dup
            result = {}
            options[:required_keys].each do |key|
                assert(data.include?(key.to_s))
                test_request_parameter(data, key, options)
                result[key.to_sym] = data[key.to_s]
            end
            options[:optional_keys].each do |key|
                if data.include?(key.to_s)
                    test_request_parameter(data, key, options)
                    result[key.to_sym] = data[key.to_s]
                end
            end
            result
        rescue
            debug "Request was:"
            debug data_str
            raise
        end
    end

    before '*' do
        if DEVELOPMENT
            response.headers['Access-Control-Allow-Origin'] = "http://localhost:8686"
        else
            if request.path[0, 5] == '/jwt/'
                response.headers['Access-Control-Allow-Origin'] = "https://dashboard.gymnasiumsteglitz.de"
            else
                response.headers['Access-Control-Allow-Origin'] = "https://agr.gymnasiumsteglitz.de"
            end
        end
        response.headers['Access-Control-Request-Headers'] = 'X-SESSION-ID,X-JWT,X-APP-VERSION'
        @latest_request_body = nil
        @latest_request_body_parsed = nil
        # before any API request, determine currently logged in user via the provided session ID
        @session_user = nil
        sid = nil
        if request.cookies.include?('sid')
            sid = request.cookies['sid']
        end
        if request.env['HTTP_X_SESSION_ID']
            sid = request.env['HTTP_X_SESSION_ID']
        end
        @session_app_version = nil
        if request.env['HTTP_X_APP_VERSION']
            @session_app_version = request.env['HTTP_X_APP_VERSION']
        end
        @session_user_agent = nil
        if request.env['HTTP_USER_AGENT']
            @session_user_agent = request.env['HTTP_USER_AGENT']
        end
        @dashboard_jwt = nil
        @dashboard_user_email = nil
        @dashboard_user_display_name = nil
        if request.env['HTTP_X_JWT']
            @dashboard_jwt = request.env['HTTP_X_JWT']
            # STDERR.puts "Got a dashboard token!"
            # 1. decode token and check integrity via HS256
            decoded_token = JWT.decode(@dashboard_jwt, JWT_APPKEY_AGRAPP, true, {:algorithm => 'HS256'}).first
            # STDERR.puts decoded_token.to_yaml
            # 2. make sure the JWT is not expired
            diff = decoded_token['exp'] - Time.now.to_i
            assert(diff >= 0)
            @dashboard_user_email = decoded_token['email']
            @dashboard_user_display_name = decoded_token['display_name']
        end

        if sid
            if (sid.is_a? String) && (sid =~ /^[0-9A-Za-z,]+$/)
                first_sid = sid.split(',').first
                if first_sid =~ /^[0-9A-Za-z]+$/
                    results = neo4j_query(<<~END_OF_QUERY, :sid => first_sid, :today => Date.today.to_s).to_a
                        MATCH (s:Session {sid: $sid})-[:BELONGS_TO]->(u:User)
                        SET u.last_access = $today
                        SET s.last_access = $today
                        RETURN s, u;
                    END_OF_QUERY
                    if results.size == 1
                        begin
                            session = results.first['s']
                            session_expiry = session[:expires]
                            if DateTime.parse(session_expiry) > DateTime.now
                                email = results.first['u'][:email]
                                @@user_info[email] ||= {
                                    :email => email,
                                    :name => email.split('@').first
                                }
                                @session_user = @@user_info[email].dup
                                @session_user[:email] = email
                            end
                        rescue
                            # something went wrong, delete the session
                            results = neo4j_query(<<~END_OF_QUERY, :sid => first_sid).to_a
                                MATCH (s:Session {sid: $sid})
                                DETACH DELETE s;
                            END_OF_QUERY
                        end
                    end
                end
            end
        end
        if request.env['REQUEST_METHOD'] != 'OPTIONS'
            if @dashboard_jwt
                debug "[#{@dashboard_user_email.split('@').first}@jwt] #{request.path}"
            else
                debug "[#{((@session_user || {})[:email] || 'anon').split('@').first}@#{@session_app_version || 'unknown'}] #{request.path} #{@session_user_agent}"
            end
        end
    end

    after '/{api|jwt}/*' do
        if @respond_content
            response.body = @respond_content
            response.headers['Content-Type'] = @respond_mimetype
            if @respond_filename
                response.headers['Content-Disposition'] = "attachment; filename=\"#{@respond_filename}\""
            end
        else
            @respond_hash ||= {}
            response.body = @respond_hash.to_json
        end
    end

    def respond(hash = {})
        @respond_hash = hash
    end

    def respond_raw_with_mimetype(content, mimetype)
        @respond_content = content
        @respond_mimetype = mimetype
    end

    def respond_raw_with_mimetype_and_filename(content, mimetype, filename)
        @respond_content = content
        @respond_mimetype = mimetype
        @respond_filename = filename
    end

    def htmlentities(s)
        @html_entities_coder ||= HTMLEntities.new
        @html_entities_coder.encode(s)
    end

    post '/api/ping' do
        respond(:pong => 'yay')
    end

    options '/api/*' do
        if DEVELOPMENT
            response.headers['Access-Control-Allow-Origin'] = "http://localhost:8686"
        else
            response.headers['Access-Control-Allow-Origin'] = "https://agr.gymnasiumsteglitz.de"
        end
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Access-Control-Allow-Origin,X-SESSION-ID,X-APP-VERSION"
        response.headers['Access-Control-Request-Headers'] = 'X-SESSION-ID,X-APP-VERSION'
    end

    options '/jwt/*' do
        if DEVELOPMENT
            response.headers['Access-Control-Allow-Origin'] = "http://localhost:8686"
        else
            response.headers['Access-Control-Allow-Origin'] = "https://dashboard.gymnasiumsteglitz.de"
        end
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Access-Control-Allow-Origin,X-JWT"
        response.headers['Access-Control-Request-Headers'] = 'X-JWT'
    end

    post '/api/login' do
        data = parse_request_data(:required_keys => [:email])
        data[:email] = data[:email].strip.downcase
        unless @@user_info.include?(data[:email])
            candidates = @@user_info.keys.select do |x|
                x[0, data[:email].size] == data[:email]
            end
            if candidates.size == 1
                data[:email] = candidates.first
            end
        end
        unless @@user_info.include?(data[:email])
            suffix = '@' + data[:email].split('@')[1]
            if @@allowed_suffixes.include?(suffix)
                @@user_info[data[:email]] ||= {
                    :email => data[:email],
                    :name => data[:email].split('@').first.split('.').map { |x| x.capitalize }.join(' ')
                }
            else
                sleep 3.0
                respond(:error => 'no_invitation_found')
            end
        end
        assert(@@user_info.include?(data[:email]))
        srand(Digest::SHA2.hexdigest(LOGIN_CODE_SALT).to_i + (Time.now.to_f * 1000000).to_i)
        random_code = (0..5).map { |x| rand(10).to_s }.join('')
        random_code = '123456' if DEVELOPMENT || data[:email] == 'max.mustermann@mail.gymnasiumsteglitz.de'
        tag = RandomTag::generate(8)
        valid_to = Time.now + 600
        result = neo4j_query(<<~END_OF_QUERY, :email => data[:email], :tag => tag, :code => random_code, :valid_to => valid_to.to_i)
            MERGE (n:User {email: $email})
            CREATE (l:LoginCode {tag: $tag, code: $code, valid_to: $valid_to})-[:BELONGS_TO]->(n)
            RETURN n, l;
        END_OF_QUERY
        unless DEVELOPMENT
            email_recipient = data[:email]
            begin
                deliver_mail do
                    to email_recipient
                    bcc SMTP_FROM
                    from SMTP_FROM

                    subject "Dein Anmeldecode lautet #{random_code}"

                    StringIO.open do |io|
                        io.puts "<p>Hallo!</p>"
                        io.puts "<p>Dein Anmeldecode lautet:</p>"
                        io.puts "<p style='font-size: 200%;'>#{random_code}</p>"
                        io.puts "<p>Der Code ist für zehn Minuten gültig. Nachdem du eingeloggt bist, bleibst du für ein ganzes Jahr eingeloggt.</p>"
        #                 link = "#{WEB_ROOT}/c/#{tag}/#{random_code}"
        #                 io.puts "<p><a href='#{link}'>#{link}</a></p>"
                        io.puts "<p>Falls du diese E-Mail nicht angefordert hast, hat jemand versucht, sich mit deiner E-Mail-Adresse anzumelden. In diesem Fall musst du nichts weiter tun (es sei denn, du befürchtest, dass jemand anderes Zugriff auf dein E-Mail-Konto hat – dann solltest du dein E-Mail-Passwort ändern).</p>"
                        io.puts "<p>Viele Grüße,<br />#{WEBSITE_MAINTAINER_NAME}</p>"
                        io.string
                    end
                end
            rescue StandardError => e
                if DEVELOPMENT
                    debug "Cannot send e-mail in DEVELOPMENT mode, continuing anyway:"
                    STDERR.puts e
                else
                    raise e
                end
            end
        end
        debug "Login for #{data[:email]}: #{tag} / #{random_code}"
        response_hash = {:tag => tag}
        respond(response_hash)
    end

    def create_session(email, expire_hours)
        sid = RandomTag::generate(24)
        assert(sid =~ /^[0-9A-Za-z]+$/)
        data = {:sid => sid,
                :expires => (DateTime.now() + expire_hours / 24.0).to_s}

        neo4j_query_expect_one(<<~END_OF_QUERY, :email => email, :data => data)
            MATCH (u:User {email: $email})
            CREATE (s:Session $data)-[:BELONGS_TO]->(u)
            RETURN s;
        END_OF_QUERY
        sid
    end

    post '/api/confirm_login' do
        data = parse_request_data(:required_keys => [:tag, :code])
        data[:code] = data[:code].gsub(/[^0-9]/, '')
        begin
            result = neo4j_query_expect_one(<<~END_OF_QUERY, :tag => data[:tag])
                MATCH (l:LoginCode {tag: $tag})-[:BELONGS_TO]->(u:User)
                SET l.tries = COALESCE(l.tries, 0) + 1
                RETURN l, u;
            END_OF_QUERY
        rescue
            respond({:error => 'code_expired'})
            assert_with_delay(false, "Code expired", true)
        end
        user = result['u']
        login_code = result['l']
        if login_code[:tries] > MAX_LOGIN_TRIES
            neo4j_query(<<~END_OF_QUERY, :tag => data[:tag])
                MATCH (l:LoginCode {tag: $tag})
                DETACH DELETE l;
            END_OF_QUERY
            respond({:error => 'code_expired'})
            assert_with_delay(false, "Code expired", true)
        end
        assert(login_code[:tries] <= MAX_LOGIN_TRIES)
        if data[:code].size != 6
            respond({:error => 'wrong_code'})
            assert_with_delay(false, "Fishy code length entered for #{user[:email]}", true)
        end
        if (data[:code] != login_code[:code])
            respond({:error => 'wrong_code'})
        end
        assert_with_delay(data[:code] == login_code[:code], "Wrong e-mail code entered for #{user[:email]}: #{data[:code]}", true)
        if Time.at(login_code[:valid_to]) < Time.now
            respond({:error => 'code_expired'})
        end
        assert(Time.at(login_code[:valid_to]) >= Time.now, 'code expired', true)
        session_id = create_session(user[:email], 365 * 24)
        neo4j_query(<<~END_OF_QUERY, :tag => data[:tag])
            MATCH (l:LoginCode {tag: $tag})
            DETACH DELETE l;
        END_OF_QUERY
        respond(:ok => 'yeah', :sid => session_id)
    end

    def require_user!
        assert(@session_user != nil)
    end

    post '/api/get_latest_timestamp' do
        if @session_user.nil?
            respond(:invalid_session_please_delete => true)
        end
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['t']
            MATCH (e:Entry)-[r:BELONGS_TO]->(u:User {email: $email})
            RETURN COALESCE(MAX(r.timestamp), 0) AS t;
        END_OF_QUERY
        respond(:timestamp => timestamp)
    end

    def get_coins()
        require_user!
        coins = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['coins']
            MATCH (u: User{ email: $email})
            RETURN COALESCE(u.coins, 0) AS coins;
        END_OF_QUERY
        coins
    end

    def set_coins(coins)
        require_user!
        neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :coins => coins})
            MATCH (u: User{ email: $email})
            SET u.coins = $coins;
        END_OF_QUERY
    end

    post '/api/get_coins' do
        respond(:coins => get_coins())
    end

    post '/api/update_coins' do
        require_user!
        data = parse_request_data(:required_keys => [:coins],
            :types => {:coins => Integer})
        if data[:coins] > get_coins()
            set_coins(data[:coins])
        end
        respond(:ok => 'yeah')
    end

    def get_active_unit_timestamp()
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['timestamp']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.unit_timestamp, 0) AS timestamp;
        END_OF_QUERY
        timestamp
    end

    def get_active_unit()
        require_user!
        unit = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['unit']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.unit, 1) AS unit;
        END_OF_QUERY
        unit
    end

    def set_active_unit(unit, timestamp)
        require_user!
        if timestamp > get_active_unit_timestamp()
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :unit => unit, :timestamp => timestamp})
                MATCH (u: User { email: $email})
                SET u.unit = $unit
                SET u.unit_timestamp = $timestamp;
            END_OF_QUERY
        end
    end

    def get_avatar_timestamp()
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['timestamp']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.avatar_timestamp, 0) AS timestamp;
        END_OF_QUERY
        timestamp
    end

    def get_avatar()
        require_user!
        unit = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['avatar']
            MATCH (u: User { email: $email})
            RETURN u.avatar AS avatar;
        END_OF_QUERY
        unit
    end

    def set_avatar(avatar, timestamp)
        require_user!
        if timestamp > get_avatar_timestamp()
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :avatar => avatar, :timestamp => timestamp})
                MATCH (u: User { email: $email})
                SET u.avatar = $avatar
                SET u.avatar_timestamp = $timestamp;
            END_OF_QUERY
        end
    end

    def get_font_timestamp()
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['timestamp']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.font_timestamp, 0) AS timestamp;
        END_OF_QUERY
        timestamp
    end

    def get_font()
        require_user!
        unit = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['font']
            MATCH (u: User { email: $email})
            RETURN u.font AS font;
        END_OF_QUERY
        unit
    end

    def set_font(font, timestamp)
        require_user!
        if timestamp > get_font_timestamp()
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :font => font, :timestamp => timestamp})
                MATCH (u: User { email: $email})
                SET u.font = $font
                SET u.font_timestamp = $timestamp;
            END_OF_QUERY
        end
    end

    def get_voc_range_timestamp()
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['timestamp']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.voc_range_timestamp, 0) AS timestamp;
        END_OF_QUERY
        timestamp
    end

    def get_voc_range()
        require_user!
        result = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.voc_range_start, 0) AS voc_range_start,
                   COALESCE(u.voc_range_length, 0) AS voc_range_length;
        END_OF_QUERY
        [result['voc_range_start'], result['voc_range_length']]
    end

    def set_voc_range(range_start, range_length, timestamp)
        require_user!
        if timestamp > get_voc_range_timestamp()
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :voc_range_start => range_start, :voc_range_length => range_length, :timestamp => timestamp})
                MATCH (u: User { email: $email})
                SET u.voc_range_start = $voc_range_start
                SET u.voc_range_length = $voc_range_length
                SET u.voc_range_timestamp = $timestamp;
            END_OF_QUERY
        end
    end

    def get_color_scheme_timestamp()
        require_user!
        timestamp = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['timestamp']
            MATCH (u: User { email: $email})
            RETURN COALESCE(u.color_scheme_timestamp, 0) AS timestamp;
        END_OF_QUERY
        timestamp
    end

    def get_color_scheme()
        require_user!
        unit = neo4j_query_expect_one(<<~END_OF_QUERY, {:email => @session_user[:email]})['color_scheme']
            MATCH (u: User { email: $email})
            RETURN u.color_scheme AS color_scheme;
        END_OF_QUERY
        unit
    end

    def set_color_scheme(color_scheme, timestamp)
        require_user!
        if timestamp > get_color_scheme_timestamp()
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :color_scheme => color_scheme, :timestamp => timestamp})
                MATCH (u: User { email: $email})
                SET u.color_scheme = $color_scheme
                SET u.color_scheme_timestamp = $timestamp;
            END_OF_QUERY
        end
    end

    post '/api/get_active_unit' do
        respond(:active_unit => get_active_unit())
    end

    post '/api/set_active_unit' do
        require_user!
        data = parse_request_data(:required_keys => [:unit, :timestamp],
            :types => {:unit => Integer, :timestamp => Integer})
        set_active_unit(data[:unit], data[:timestamp])
        respond(:active_unit => get_active_unit())
    end

    post '/api/store_events' do
        require_user!
        data = parse_request_data(:required_keys => [:words],
            :max_body_length => 0x100000, :types => {:words => Hash})
        transaction do
            data[:words].each_pair do |word, timestamp|
                neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :sha1 => word, :timestamp => timestamp})
                    MATCH (u:User {email: $email})
                    MERGE (e:Entry {sha1: $sha1})
                    MERGE (e)-[r:BELONGS_TO]->(u)
                    SET r.timestamp = CASE WHEN $timestamp > COALESCE(r.timestamp, 0) THEN $timestamp ELSE r.timestamp END;
                END_OF_QUERY
                self.class.add_entry_to_cache(@session_user[:email], word, timestamp)
            end
        end
        respond(:success => 'yay')
    end

    post '/api/fetch_events' do
        require_user!
        data = parse_request_data(:required_keys => [:timestamp],
            :types => {:timestamp => Integer})

        rows = neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :timestamp => data[:timestamp]}).map { |x| {:sha1 => x['sha1'], :timestamp => x['timestamp']} }
            MATCH (e:Entry)-[r:BELONGS_TO]->(u:User {email: $email})
            WHERE r.timestamp >= $timestamp
            RETURN e.sha1 AS sha1, r.timestamp AS timestamp;
        END_OF_QUERY
        respond(:events => rows)
    end

    def whoami
        require_user!
        result = {
            :email => @session_user[:email],
            :user_name => @session_user[:name],
            :nc_login => @session_user[:nc_login],
            :coins => get_coins(),
            :shop_items => get_shop_items(),
            :active_unit => get_active_unit(),
            :active_unit_timestamp => get_active_unit_timestamp(),
            :avatar => get_avatar(),
            :avatar_timestamp => get_avatar_timestamp(),
            :color_scheme => get_color_scheme(),
            :color_scheme_timestamp => get_color_scheme_timestamp(),
            :font => get_font(),
            :font_timestamp => get_font_timestamp(),
            :voc_range => get_voc_range(),
            :voc_range_timestamp => get_voc_range_timestamp(),
        }
        result
    end

    post '/api/whoami' do
        respond(whoami())
    end

    post '/api/update_profile' do
        require_user!
        data = parse_request_data(:optional_keys => [:coins,
            :active_unit, :active_unit_timestamp,
            :avatar, :avatar_timestamp,
            :color_scheme, :color_scheme_timestamp,
            :font, :font_timestamp,
            :voc_range_start, :voc_range_length, :voc_range_timestamp],
            :types => {:coins => Integer, :active_unit => Integer,
                       :active_unit_timestamp => Integer, :avatar_timestamp => Integer,
                       :color_scheme_timestamp => Integer, :font_timestamp => Integer,
                       :voc_range_start => Integer, :voc_range_length => Integer,
                       :voc_range_timestamp => Integer})
        if data[:coins]
            if data[:coins] > get_coins()
                set_coins(data[:coins])
            end
        end
        if data[:active_unit] && data[:active_unit_timestamp]
            set_active_unit(data[:active_unit], data[:active_unit_timestamp])
        end
        if data[:avatar] && data[:avatar_timestamp]
            set_avatar(data[:avatar], data[:avatar_timestamp])
        end
        if data[:color_scheme] && data[:color_scheme_timestamp]
            set_color_scheme(data[:color_scheme], data[:color_scheme_timestamp])
        end
        if data[:font] && data[:font_timestamp]
            set_font(data[:font], data[:font_timestamp])
        end
        if data[:voc_range_start] && data[:voc_range_length] && data[:voc_range_timestamp]
            set_voc_range(data[:voc_range_start], data[:voc_range_length], data[:voc_range_timestamp])
        end
        if @session_app_version
            self.class.update_version_for_user(@session_user[:email], @session_app_version)
        end
        respond(whoami())
    end

    post '/api/shop' do
        require_user!
        respond(:shop => @@shop)
    end

    def get_shop_items()
        rows = neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email]}).map { |x| {:item => x['s'], :price => x['price']} }
            MATCH (u: User{ email: $email})-[r:PURCHASED]->(s:ShopItem)
            RETURN s, r.price AS price;
        END_OF_QUERY
        result = {}
        purchase_sum = 0
        rows.each do |item|
            result["#{item[:item][:category]}/#{item[:item][:item]}"] = item[:price]
            purchase_sum += item[:price]
        end
        respond(:items => result, :purchase_sum => purchase_sum)
    end

    post '/api/purchase' do
        require_user!
        data = parse_request_data(:required_keys => [:category, :item])
        category = data[:category]
        item = data[:item]
        assert(@@shop.include?(category))
        assert(@@shop[category].include?(item))
        transaction do
            purchased_items = get_shop_items()[:items]
            assert(!purchased_items.include?("#{data[:category]}/#{data[:item]}"))
            price = @@shop[category][item]
            current_coins = get_coins()
            if price > current_coins
                respond(:error => 'not_enough_coins')
            end
            neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :category => category, :item => item, :price => price})
                MATCH (u: User{ email: $email})
                MERGE (s:ShopItem {category: $category, item: $item})
                CREATE (u)-[:PURCHASED {price: $price}]->(s);
            END_OF_QUERY
        end
        shop_items = get_shop_items()
        respond(:new_shop_items => shop_items)
    end

    post '/api/activate_hades' do
        require_user!
        category = 'avatars'
        item = 'hades'
        price = 0
        neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :category => category, :item => item, :price => price})
            MATCH (u: User {email: $email})
            MERGE (s:ShopItem {category: $category, item: $item})
            CREATE (u)-[:PURCHASED {price: $price}]->(s);
        END_OF_QUERY
        shop_items = get_shop_items()
        respond(:result => 'Herzlichen Glückwunsch, du besitzt nun Hades, den Herrscher der Unterwelt. Synchronisiere deine App bitte einmal, dann kannst du ihn auswählen.')
    end

    get '/togoogleplay' do
        redirect 'https://play.google.com/store/apps/details?id=de.gymnasiumsteglitz.agr_app', 302
    end

    get '/toappstore' do
        redirect 'https://apps.apple.com/de/app/id1597703481', 302
    end

    get '/*' do
        ''
    end

    def require_dashboard_jwt!
        assert(!@dashboard_jwt.nil?)
    end

    post '/jwt/dashboard_ping' do
        require_dashboard_jwt!
        respond(:pong => 'dashboard connection working', :welcome => @dashboard_user_display_name)
    end

    post '/jwt/overview_stats' do
        require_dashboard_jwt!
        result = {}

        t1 = (Time.now.to_i - 3600 * 24 * 1) * 1000
        t7 = (Time.now.to_i - 3600 * 24 * 7) * 1000
        t28 = (Time.now.to_i - 3600 * 24 * 28) * 1000

        td1 = 0
        td7 = 0
        td28 = 0
        tdall = 0

        tvd1 = 0
        tvd7 = 0
        tvd28 = 0
        tvdall = 0

        tfd1 = 0
        tfd7 = 0
        tfd28 = 0
        tfdall = 0

        ud1 = Set.new()
        ud7 = Set.new()
        ud28 = Set.new()
        udall = Set.new()

        tu = {}

        @@cache[:entries].each_pair do |sha1, users|
            is_voc = @@voc_data['words'].include?(sha1)
            is_form = @@sphinx_data['forms'].include?(sha1)
            users.each_pair do |email, t|
                tu[email] ||= {:t1d => 0, :t7d => 0, :t28d => 0, :tall => 0}
                if t > t1
                    td1 += 1
                    tvd1 += 1 if is_voc
                    tfd1 += 1 if is_form
                    tu[email][:t1d] += 1
                end
                if t > t7
                    td7 += 1
                    tvd7 += 1 if is_voc
                    tfd7 += 1 if is_form
                    tu[email][:t7d] += 1
                end
                if t > t28
                    td28 += 1
                    tvd28 += 1 if is_voc
                    tfd28 += 1 if is_form
                    tu[email][:t28d] += 1
                end
                tdall += 1
                tvdall += 1 if is_voc
                tfdall += 1 if is_form
                tu[email][:tall] += 1

                ud1 << email if t > t1
                ud7 << email if t > t7
                ud28 << email if t > t28
                udall << email
            end
        end
        result[:tasks_solved_1d] = td1
        result[:tasks_solved_7d] = td7
        result[:tasks_solved_28d] = td28
        result[:tasks_solved_all] = tdall

        result[:tasks_voc_solved_1d] = tvd1
        result[:tasks_voc_solved_7d] = tvd7
        result[:tasks_voc_solved_28d] = tvd28
        result[:tasks_voc_solved_all] = tvdall

        result[:tasks_form_solved_1d] = tfd1
        result[:tasks_form_solved_7d] = tfd7
        result[:tasks_form_solved_28d] = tfd28
        result[:tasks_form_solved_all] = tfdall

        result[:users_solved_1d] = ud1.size
        result[:users_solved_7d] = ud7.size
        result[:users_solved_28d] = ud28.size
        result[:users_solved_all] = udall.size

        result[:user_top_list] = []
        result[:user_info] = {}
        @@cache[:users].keys.sort do |a, b|
            @@cache[:users][b].size <=> @@cache[:users][a].size
        end.each do |email|
            t = @@cache[:last_timestamp_for_user][email]
            result[:user_top_list] << {
                :email => email,
                :solved => @@cache[:users][email].size,
                :last_activity => t,
                :st => tu[email]
            }
            cat = 'all'
            cat = '28d' if t > t28
            cat = '7d' if t > t7
            cat = '1d' if t > t1
            result[:user_info][email] = {
                :last_activity_cat => cat,
                :version => @@cache[:latest_version_for_user][email]
            }
        end
        result[:unit_for_user] = {}
        neo4j_query(<<~END_OF_QUERY).each do |row|
            MATCH (u:User)
            RETURN u.email AS email, COALESCE(u.unit, 1) AS unit;
        END_OF_QUERY
            result[:unit_for_user][row['email']] = row['unit']
        end
        respond(:result => result)
    end

    post '/jwt/user_details' do
        require_dashboard_jwt!
        data = parse_request_data(:required_keys => [:email])

        result = {
            :entries => {},
            :now => Time.now.to_i * 1000,
        }

        neo4j_query(<<~END_OF_QUERY, {:email => data[:email]}).each do |row|
            MATCH (e:Entry)-[r:BELONGS_TO]->(u:User {email: $email})
            RETURN e.sha1 AS sha1, r.timestamp AS t;
        END_OF_QUERY
            result[:entries][row['sha1']] = row['t']
        end

        respond(:result => result)
    end

    post '/jwt/get_voc' do
        require_dashboard_jwt!
        respond(:voc => @@voc_data)
    end

    after '*' do
        cleanup_neo4j()
    end

end
