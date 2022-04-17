var editor = null;
var term = null;
var fitAddon = null;
var process_running = false;
var ws = null;
var input = null;
var message_queue = [];
var shown_passed_modal = false;
window.interval = null;
window.message_to_append = null;
window.message_to_append_index = 0;
window.message_to_append_timestamp = 0.0;

jQuery.extend({
    getQueryParameters : function(str) {
        return (str || document.location.search).replace(/(^\?)/,'').split("&").map(function(n){
            return n = n.split("="), this[n[0]] = n[1], this
        }.bind({}))[0];
    }
});

function show_error_message(message)
{
    var div = $('<div>').css('text-align', 'center').css('padding', '15px').addClass('bg-light text-danger').html(message);
    $('.api_messages').empty();
    $('.api_messages').append(div).show();
}

function show_success_message(message)
{
    var div = $('<div>').css('text-align', 'center').css('padding', '15px').addClass('bg-light text-success').html(message);
    $('.api_messages').empty();
    $('.api_messages').append(div).show();
}

function api_call(url, data, callback, options)
{
    if (typeof(options) === 'undefined')
        options = {};
    
    if (typeof(window.please_wait_timeout) !== 'undefined')
        clearTimeout(window.please_wait_timeout);
    
    if (options.no_please_wait !== true)
    {
        // show 'please wait' message after 500 ms
        (function() {
            window.please_wait_timeout = setTimeout(function() {
                var div = $('<div>').css('text-align', 'center').css('padding', '15px').addClass('text-muted').html("<i class='fa fa-cog fa-spin'></i>&nbsp;&nbsp;Einen Moment bitte...");
                $('.api_messages').empty().show();
                $('.api_messages').append(div);
            }, 500);
        })();
    }
    
    var jqxhr = jQuery.post({
        url: url,
        data: JSON.stringify(data),
        contentType: 'application/json',
        dataType: 'json'
    });
    
    jqxhr.done(function(data) {
        clearTimeout(window.please_wait_timeout);
        $('.api_messages').empty().hide();
        if (typeof(callback) !== 'undefined')
        {
            data.success = true;
            callback(data);
        }
    });
    
    jqxhr.fail(function(http) {
        clearTimeout(window.please_wait_timeout);
        $('.api_messages').empty();
        show_error_message('Bei der Bearbeitung der Anfrage ist ein Fehler aufgetreten.');
        if (typeof(callback) !== 'undefined')
        {
            var error_message = 'unknown_error';
            try {
                error_message = JSON.parse(http.responseText)['error'];
            } catch(err) {
            }
            console.log(error_message);
            callback({success: false, error: error_message});
        }
    });
}

function perform_logout()
{
    api_call('/api/logout', {}, function(data) {
        if (data.success)
            window.location.href = '/';
    });
}
