# -------------------------------------------------------------------
# Diese Datei bitte unter credentials.rb speichern und Werte anpassen
# (bitte keine Credentials in Git committen)
# -------------------------------------------------------------------

DEVELOPMENT = ENV['DEVELOPMENT']

SMTP_SERVER = 'smtp.example.com'
IMAP_SERVER = 'imap.example.com'
SMTP_USER = 'dashboard@beispielschule.de'
SMTP_PASSWORD = '1234_nein_wirklich'
SMTP_DOMAIN = 'beispielschule.de'
SMTP_FROM = 'Dashboard Beispielschule <dashboard@beispielschule.de>'

if defined? Mail
    Mail.defaults do
    delivery_method :smtp, { 
        :address => SMTP_SERVER,
        :port => 587,
        :domain => SMTP_DOMAIN,
        :user_name => SMTP_USER,
        :password => SMTP_PASSWORD,
        :authentication => 'login',
        :enable_starttls_auto => true  
    }
    end
end

WEBSITE_HOST = 'lang.beispielschule.de'
WEBSITE_MAINTAINER_NAME = 'Herr Müller'
WEB_ROOT = DEVELOPMENT ? 'http://localhost:8025' : "https://#{WEBSITE_HOST}"

LOGIN_CODE_SALT = 'insert_salt_here'