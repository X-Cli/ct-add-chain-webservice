(function(){
    "use strict"


    function reset_button_cert_handler() {
        var submit_btn = $('#submit_cert')
        var form = $('#form_cert')
        submit_btn.val('Add Chain')
        form.submit(click_submit_button_cert_handler)
    }

    function error_popup_initialization(error) {
        var alert_dialog = $('#alert_dialog')
        var alert_container = $('#alert_container')
        alert_container.text('Operation failed: ' + error)
        alert_dialog.show()
    }

    function error_cert_handler(jqXHR, text_status, error_thrown) {
        error_popup_initialization(error_thrown)
        reset_button_cert_handler()
    }

    function success_modal_initialization(data) {
        var result_modal = $('#logresults')
        var result_container = document.getElementById('result_container')

        // Reset the list
        if(result_container.childNodes.length > 0) {
            for(var i = result_container.childNodes.length -1; i >= 0 ; i--) {
                result_container.removeChild(result_container.childNodes[i])
            }
        }
        var div = document.createElement('div')
        var errors = document.createElement('ul')

        if(!('scts' in data)) {
            error_cert_handler(null, null, 'Invalid response; scts key missing')
            return
        }
        else {
            var sct_count = 0
            var error_count = 0
            for(var log in data['scts']) {
                if('sct' in data['scts'][log] && 'valid' in data['scts'][log] && data['scts'][log]['valid']) {
                    var a = document.createElement('a')
                    var txt = document.createTextNode(log)
                    a.appendChild(txt)
                    a.setAttribute('class', 'list-group-item')
                    a.setAttribute('href', 'data:application/octet-stream;base64,' + data['scts'][log]['sct'])
                    a.setAttribute('download', log + '.sct')
                    div.appendChild(a)
                    sct_count += 1
                }
                else if ('error' in data['scts'][log]) {
                    var li = document.createElement('li')
                    var txt = document.createTextNode(log + ': ' + data['scts'][log]['error'])
                    li.appendChild(txt)
                    errors.appendChild(li)
                    error_count += 1
                }
            }
            if(sct_count == 0) {
                result_container.appendChild(document.createTextNode('No log accepted your certificate chain.' +
                    'No one loves you. Just kidding, but I have nothing for you, sorry.'))
            }
            else {
                div.setAttribute('class', 'list-group')
                var p = document.createElement('p')
                var txt = document.createTextNode(
                    'Here are the valid SCTs that have been retrieved. '+
                    'You may click on the log names in the following list to download them:'
                )
                p.appendChild(txt)
                div.insertBefore(p, div.firstChild)
                result_container.appendChild(div)
            }
            if (error_count > 0) {
                p = document.createElement('p')
                txt = document.createTextNode('Errors:')
                p.appendChild(txt)
                result_container.appendChild(p)
                result_container.appendChild(errors)
            }

        }
        result_modal.modal({backdrop: 'static'})
    }

    function success_cert_handler(data, text_status, jqXHR) {
        success_modal_initialization(data)
        reset_button_cert_handler()
    }

    function send_request(chain, success_handler, error_handler, intv) {
        $.ajax({
            method: 'POST',
            url: '/submit',
            timeout: 120 * 1000,
            cache: false,
            dataType: 'json',
            data: {
                cert: chain
            },
            jsonp: false,
            success: function(data, text_status, jqXHR) {
                clearInterval(intv)
                success_handler(data, text_status, jqXHR)
            },
            error: function(jqXHR, text_status, error_thrown) {
                clearInterval(intv)
                error_handler(jqXHR, text_status, error_thrown)
            }
        })
    }

    function click_submit_button_cert_handler(evt) {
        var pem_chain = $('#cert_textarea').val()

        var submit_btn = $('#submit_cert')
        submit_btn.val('Working...')
        var counter = 120
        var intv = setInterval(function() {
            counter -= 1
            if (counter > 0) {
                submit_btn.val('Working... ('+counter+')')
            } else {
                clearInterval(intv)
                submit_btn.val('Timed out :/')
            }
        }, 1000);
        var form = $('#form_cert')
        form.unbind('click', click_submit_button_cert_handler)

        send_request(pem_chain, success_cert_handler, error_cert_handler, intv)

        evt.preventDefault()
    }

    function reset_button_upload_handler() {
        var submit_btn = $('#submit_upload')
        var form = $('#form_upload')
        submit_btn.val('Add Chain')
        form.submit(click_submit_button_upload_handler)
    }

    function error_upload_handler(jqXHR, text_status, error_thrown) {
        error_popup_initialization(error_thrown)
        reset_button_upload_handler()
    }

    function success_upload_handler(data, text_status, jqXHR) {
        success_modal_initialization(data)
        reset_button_upload_handler()
    }

    function click_submit_button_upload_handler(evt) {
        var submit_btn = $('#submit_upload')
        submit_btn.val('Working...')
        var counter = 120
        var intv = setInterval(function() {
            counter -= 1
            if (counter > 0) {
                submit_btn.val('Working... ('+counter+')')
            } else {
                clearInterval(intv)
                submit_btn.val('Timed out :/')
            }
        }, 1000);
        var form = $('#form_Upload')
        form.unbind('click', click_submit_button_upload_handler)

        var file_input = $('#cert_file').get(0)
        if(file_input.files.length == 0) {
            error_upload_handler(null, null, 'No input file.')
        }
        else {
            var file = file_input.files[0]
            var fr = new FileReader()
            fr.onload = function() {
                send_request(fr.result, success_upload_handler, error_upload_handler, intv)
            }
            fr.readAsText(file)
        }
        evt.preventDefault()
    }



    function configure_copy_paste_form() {
        $('#form_cert').submit(click_submit_button_cert_handler)
    }

    function configure_upload_form() {
        $('#form_upload').submit(click_submit_button_upload_handler)
    }

    function configure_alert_dialog() {
        $('#alert_dialog').hide()
        $('#alert_close').click(function() {
            $('#alert_dialog').hide()
        })
    }

    $(document).ready(function() {
        configure_copy_paste_form()
        configure_upload_form()
        configure_alert_dialog()
    })

})()