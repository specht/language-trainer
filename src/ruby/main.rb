require 'json'
require 'neo4j_ruby_driver'
require 'sinatra/base'
require 'sinatra/cookies'
require 'mail'

require './credentials.template.rb'
warn_level = $VERBOSE
$VERBOSE = nil
require './credentials.rb'
$VERBOSE = warn_level
DASHBOARD_SERVICE = ENV['DASHBOARD_SERVICE']

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

module QtsNeo4j

    class CypherError < StandardError
        def initialize(code, message)
            @code = code
            @message = message
        end

        def to_s
            "Cypher Error\n#{@code}\n#{@message}"
        end
    end

    def transaction(&block)
        @@neo4j_driver ||= Neo4j::Driver::GraphDatabase.driver('bolt://neo4j:7687')
        if @has_bolt_session.nil?
            begin
                @has_bolt_session = true
                @@neo4j_driver.session do |session|
                    if @has_bolt_transaction.nil?
                        begin
                            session.write_transaction do |tx|
                                @has_bolt_transaction = tx
                                yield
                            end
                        ensure
                            @has_bolt_transaction = nil
                        end
                    else
                        yield
                    end
                end
            rescue StandardError => e
                debug("[NEO4J ERROR] #{e}")
            ensure
                @has_bolt_session = nil
            end
        else
            yield
        end
    end

    class ResultRow
        def initialize(v)
            @v = Hash[v.map { |k, v| [k.to_sym, v] }]
        end

        def props
            @v
        end
    end

    def wait_for_neo4j
        delay = 1
        10.times do
            begin
                neo4j_query("MATCH (n) RETURN n LIMIT 1;")
                break
            rescue
                STDERR.puts $!
                STDERR.puts "Retrying after #{delay} seconds..."
                sleep delay
                delay += 1
            end
        end
    end

    def parse_neo4j_result(x)
        if x.is_a?(Neo4j::Driver::Types::Node) || x.is_a?(Neo4j::Driver::Types::Relationship)
            #ResultRow.new(x.properties)
            v = x.properties
            Hash[v.map { |k, v| [k.to_sym, v] }]
        elsif x.is_a?(Array)
            x.map { |y| parse_neo4j_result(y) }
        else
            x
        end
    end

    def neo4j_query(query_str, options = {})
        # TODO: In preparation for migration from Neo4j 3 to 4, replace $key syntax with $key
        # TODO: Make this stand out, fix the code by and by
        # options.keys.each do |key|
            # query_str.gsub!("{#{key}}", "$#{key}")
        # end
        # if DEVELOPMENT
        #     debug(query_str, 1) 
        #     debug(options.to_json, 1)
        # end
        # return
        transaction do
            temp_result = nil
            temp_result = @has_bolt_transaction.run(query_str, options)

            result = []
            temp_result.each do |row|
                item = {}
                row.keys.each.with_index do |key, i|
                    v = row.values[i]
                    item[key.to_s] = parse_neo4j_result(v)
                end
                result << item
            end
            result
        end
    end

    def neo4j_query_expect_one(query_str, options = {})
        result = neo4j_query(query_str, options)
        unless result.size == 1
            if DEVELOPMENT
                debug '-' * 40
                debug query_str
                debug options.to_json
                debug '-' * 40
            end
            raise "Expected one result but got #{result.size}"
        end
        result.first
    end
end

class Neo4jGlobal
    include QtsNeo4j
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
    include QtsNeo4j

    def setup(main)
        wait_for_neo4j
        delay = 1
        10.times do
            begin
                neo4j_query("MATCH (n) RETURN n LIMIT 1;")
                break unless ENV['DASHBOARD_SERVICE'] == 'ruby'
                transaction do
                    debug "Setting up constraints and indexes..."
                    neo4j_query("CREATE CONSTRAINT ON (n:LoginCode) ASSERT n.tag IS UNIQUE")
                    neo4j_query("CREATE CONSTRAINT ON (n:User) ASSERT n.email IS UNIQUE")
                    neo4j_query("CREATE CONSTRAINT ON (n:Entry) ASSERT n.sha1 IS UNIQUE")
                    # neo4j_query("CREATE INDEX ON :Entry(sha1)")
                    neo4j_query("CALL db.index.fulltext.createRelationshipIndex('belongs_to_timestamp_index', ['BELONGS_TO'], ['timestamp']);
                    ")
                end
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
    include QtsNeo4j
    helpers Sinatra::Cookies

    configure do
        set :show_exceptions, false
    end

    def self.collect_data
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
        @@user_info['max.mustermann@mail.gymnasiumsteglitz.de'] = {:name => 'Max Mustermann', :nc_login => 'max.mustermann'}
        @@shop = YAML.load(File.read('shop.yaml'))
        @@voc_data = JSON.load(File.read('/repos/agr-app/flutter/data/voc.json'))
        @@sphinx_data = JSON.load(File.read('/repos/agr-app/flutter/data/sphinx-haul.json'))
        STDERR.puts "Voc: #{@@voc_data['words'].size}"
        STDERR.puts "Sphinx forms: #{@@sphinx_data['forms'].size}"
        # emails = $neo4j.neo4j_query(<<~END_OF_QUERY).map { |x| x['email'] }
        #     MATCH (u:User) RETURN u.email AS email;
        # END_OF_QUERY
        # STDERR.print "Fetching data for users..."
        # emails.each do |email|
        #     rows = $neo4j.neo4j_query(<<~END_OF_QUERY, {:email => email})
        #         MATCH (e:Entry)-[r:BELONGS_TO]->(u:User {email: $email}) RETURN r.timestamp AS t, e.sha1 AS sha1;
        #     END_OF_QUERY
        #     rows.each do |row|
        #         t = row['t']
        #         sha1 = row['sha1']
        #     end
        # end
        # STDERR.puts
    end

    def nav_items()
        StringIO.open do |io|
            nav_items = []
            if @session_user
                nav_items << ['/', 'Übersicht', 'fa fa-calendar']
            else
                nav_items << ['/', 'Anmelden', 'fa fa-sign-in']
            end
            return nil if nav_items.empty?
            io.puts "<button class='navbar-toggler' type='button' data-toggle='collapse' data-target='#navbarTogglerDemo02' aria-controls='navbarTogglerDemo02' aria-expanded='false' aria-label='Toggle navigation'>"
            io.puts "<span class='navbar-toggler-icon'></span>"
            io.puts "</button>"
            io.puts "<div class='collapse navbar-collapse my-0 flex-grow-0' id='navbarTogglerDemo02'>"
            io.puts "<ul class='navbar-nav mr-auto'>"
            nav_items.each do |x|
                io.puts "<li class='nav-item text-nowrap'>"
                io.puts "<a class='nav-link nav-icon' href='#{x[0]}' #{x[3]}><div class='icon'><i class='#{x[2]}'></i></div>#{x[1]}</a>"
                io.puts "</li>"
            end
            io.puts "</ul>"
            io.puts "</div>"
            io.string
        end
    end

    def self.compile_files(key, mimetype, paths)
        @@compiled_files[key] ||= {:timestamp => nil, :content => nil}
        
        latest_file_timestamp = paths.map do |path|
            File.mtime(File.join('/static', path))
        end.max
        
        if @@compiled_files[key][:timestamp].nil? || @@compiled_files[key][:timestamp] < latest_file_timestamp
            @@compiled_files[key][:content] = StringIO.open do |io|
                paths.each do |path|
                    io.puts File.read(File.join('/static', path))
                end
                io.string
            end
            @@compiled_files[key][:sha1] = Digest::SHA1.hexdigest(@@compiled_files[key][:content])[0, 16]
            @@compiled_files[key][:timestamp] = latest_file_timestamp
        end
    end
    
    def self.compile_js()
        files = [
            '/bower_components/jquery/dist/jquery.min.js',
            '/bower_components/popper.js/popper.min.js',
            '/bower_components/bootstrap/bootstrap.min.js',
            '/code.js',
        ]
        
        self.compile_files(:js, 'application/javascript', files)
        FileUtils::rm_rf('/gen/js/')
        FileUtils::mkpath('/gen/js/')
        File.open("/gen/js/compiled-#{@@compiled_files[:js][:sha1]}.js", 'w') do |f|
            f.print(@@compiled_files[:js][:content])
        end
    end
    
    def self.compile_css()
        files = [
            '/bower_components/bootstrap/bootstrap.min.css',
            '/css/styles.css',
        ]
        
        self.compile_files(:css, 'text/css', files)
        FileUtils::rm_rf('/gen/css/')
        FileUtils::mkpath('/gen/css/')
        File.open("/gen/css/compiled-#{@@compiled_files[:css][:sha1]}.css", 'w') do |f|
            f.print(@@compiled_files[:css][:content])
        end
    end

    configure do
        self.collect_data() unless defined?(SKIP_COLLECT_DATA) && SKIP_COLLECT_DATA
        if ENV['SERVICE'] == 'ruby' && (File.basename($0) == 'thin' || File.basename($0) == 'pry.rb')
            setup = SetupDatabase.new()
            setup.setup(self)
            @@compiled_files = {}
            self.compile_js()
            self.compile_css()
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
        if DEVELOPMENT && request.path[0, 5] != '/api/'
            self.class.compile_js()
            self.class.compile_css()
        end
        response.headers['Access-Control-Allow-Origin'] = "https://agr.gymnasiumsteglitz.de"
        response.headers['Access-Control-Request-Headers'] = 'X-SESSION-ID'
        @latest_request_body = nil
        @latest_request_body_parsed = nil
        # before any API request, determine currently logged in user via the provided session ID
        @session_user = nil
        sid = nil
        if request.cookies.include?('sid')
            sid = request.cookies['sid']
        end
        # STDERR.puts request.headers.to_yaml
        if request.env['HTTP_X_SESSION_ID']
            sid = request.env['HTTP_X_SESSION_ID']
        end
        app_version = nil
        if request.env['HTTP_X_APP_VERSION']
            app_version = request.env['HTTP_X_APP_VERSION']
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
        debug "[#{((@session_user || {})[:email] || 'anon').split('@').first}@#{app_version || 'unknown'}] #{request.path}"
    end

    after '/api/*' do
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
        response.headers['Access-Control-Allow-Origin'] = "https://agr.gymnasiumsteglitz.de"
        response.headers['Access-Control-Allow-Headers'] = "Content-Type, Access-Control-Allow-Origin,X-SESSION-ID"
        response.headers['Access-Control-Request-Headers'] = 'X-SESSION-ID'
    end

    post '/api/login' do
        data = parse_request_data(:required_keys => [:email])
        data[:email] = data[:email].strip.downcase
        unless @@user_info.include?(data[:email])
            sleep 3.0
            respond(:error => 'no_invitation_found')
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
                        io.puts "<p>Falls du diese E-Mail nicht angefordert hast, hat jemand versucht, sich mit deiner E-Mail-Adresse auf <a href='https://#{WEBSITE_HOST}/'>https://#{WEBSITE_HOST}/</a> anzumelden. In diesem Fall musst du nichts weiter tun (es sei denn, du befürchtest, dass jemand anderes Zugriff auf dein E-Mail-Konto hat – dann solltest du dein E-Mail-Passwort ändern).</p>"
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
            :font_timestamp => get_font_timestamp()
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
            :font, :font_timestamp],
            :types => {:coins => Integer, :active_unit => Integer, :active_unit_timestamp => Integer,
                       :avatar_timestamp => Integer, :color_scheme_timestamp => Integer, :font_timestamp => Integer})
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
        shop_items = get_shop_items()
        respond(:new_shop_items => shop_items)
    end

    post '/api/activate_hades' do
        require_user!
        category = 'avatars'
        item = 'hades'
        price = 0
        neo4j_query(<<~END_OF_QUERY, {:email => @session_user[:email], :category => category, :item => item, :price => price})
            MATCH (u: User{ email: $email})
            MERGE (s:ShopItem {category: $category, item: $item})
            CREATE (u)-[:PURCHASED {price: $price}]->(s);
        END_OF_QUERY
        shop_items = get_shop_items()
        respond(:result => 'Herzlichen Glückwunsch, du besitzt nun Hades, den Herrscher der Unterwelt. Synchronisiere deine App bitte einmal, dann kannst du ihn auswählen.')
    end

    get '/*' do
        path = request.env['REQUEST_PATH']
        assert(path[0] == '/')
        path = path[1, path.size - 1]
        path = 'index' if path.empty?
        path = path.split('/').first
        if path.include?('..') || (path[0] == '/')
            status 404
            return
        end
        
        @page_title = ''
        @page_description = ''
        
        font_family = 'Alegreya'
        
        unless path.include?('/')
            unless path.include?('.') || path[0] == '_'
                original_path = path.dup
                
                path = File::join('/static', path) + '.html'
                if File::exists?(path)
                    content = File::read(path, :encoding => 'utf-8')
                    
                    @original_path = original_path
                    if original_path == 'c'
                        parts = request.env['REQUEST_PATH'].split('/')
                        login_tag = parts[2]
                        login_code = parts[3]
                    end
                    
                    template_path = '_template'
                    template_path = "/static/#{template_path}.html"
                    @template ||= {}
                    @template[template_path] ||= File::read(template_path, :encoding => 'utf-8')
                    
                    s = @template[template_path].dup
                    s.sub!('#{CONTENT}', content)
                    # purge_missing_sessions()
                    page_css = ''
                    if File::exist?(path.sub('.html', '.css'))
                        page_css = "<style>\n#{File::read(path.sub('.html', '.css'))}\n</style>"
                    end
                    s.sub!('#{PAGE_CSS_HERE}', page_css)
                    compiled_js_sha1 = @@compiled_files[:js][:sha1]
                    compiled_css_sha1 = @@compiled_files[:css][:sha1]
                    meta_tags = ''

                    while true
                        index = s.index('#{')
                        break if index.nil?
                        length = 2
                        balance = 1
                        while index + length < s.size && balance > 0
                            c = s[index + length]
                            balance -= 1 if c == '}'
                            balance += 1 if c == '{'
                            length += 1
                        end
                        code = s[index + 2, length - 3]
                        begin
#                             STDERR.puts code
                            s[index, length] = eval(code).to_s || ''
                        rescue
                            debug "Error while evaluating for #{(@session_user || {})[:email]}:"
                            debug code
                            # raise
                            s[index, length] = ''
                        end
                    end
                    s.gsub!('<!--PAGE_TITLE-->', @page_title)
                    s.gsub!('<!--PAGE_DESCRIPTION-->', @page_description)
                    s
                else
                    status 404
                end
            else
                status 404
            end
        else
            status 404
        end
    end

end
