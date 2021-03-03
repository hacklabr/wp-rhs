jQuery( function( $ ) {

    $(function () {
        var valid_mail_msg =  "Preencha corretamente o seu e-mail.";
        var contact_msg_limit = 1500;

        jQuery.validator.setDefaults({
            debug: true,
            focusCleanup: true
        });

        $('#register').validate({
            errorElement: 'p',
            errorClass: 'block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                mail: {
                    required: true,
                    email: true,
                    check_email_exist: true
                },
                mail_confirm: {
                    required: true,
                    email: true,
                    check_email_exist: true,
                    equalTo: "input[name='mail']"
                },
                pass: {
                    required: true,
                    minlength: 5
                },
                pass2: {
                    required: true,
                    equalTo: "input[name='pass']"
                },
                first_name: {
                    required: true
                },
                last_name: {
                    required: true
                },
                estado: {
                    required: true
                },
                municipio: {
                    required: true
                },
                
                hiddenRecaptcha: {
                    required: function () {
                        return grecaptcha.getResponse() == '';
                    }
                }
            },
            messages: {
                mail: {
                    required: "Preencha com o seu e-mail.",
                    email: valid_mail_msg,
                    check_email_exist: "E-mail já existente, escolha outro."
                },
                mail_confirm: {
                    required: "Favor confirmar seu e-mail.",
                    email: valid_mail_msg,
                    equalTo: "Atenção: A confirmação do e-mail não corresponde ao e-mail informado"
                },
                pass: {
                    required: "Preencha com a sua senha.",
                    minlength: "Sua senha deve ser acima de 5 caracteres!"
                },
                pass2: {
                    required: "Preencha com a sua senha.",
                    equalTo: "Senhas diferentes!"
                },
                first_name: {
                    required: "Preencha com o seu primeiro nome."
                },
                last_name: {
                    required: "Preencha com o seu último nome."
                },
                estado: {
                    required: "Preencha com o seu estado."
                },
                municipio: {
                    required: "Preencha com o seu município."
                },
                hiddenRecaptcha: {
                    required: "Valide o captcha primeiro."
                }
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {

                if (element.parents(".col-sm-7").size() > 0) {
                    error.appendTo(element.parents(".form-group").find('.help-block'));
                } else if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {

                if ( !$( element ).next( "span" )[ 0 ] ) {
                    $("<span class='glyphicon glyphicon-remove form-control-feedback'></span>").insertAfter($(element));
                }
                if($(element).parent().find('.capt')){
                    $("span").hide();
                }
                $(element).closest('.form-group').addClass('has-error');
                $( element ).next( "span" ).addClass( "glyphicon-remove" ).removeClass( "glyphicon-ok" );
            },
            unhighlight: function (element) {

                if ( !$( element ).next( "span" )[ 0 ] ) {
                    $("<span class='glyphicon glyphicon-okay form-control-feedback'></span>").insertAfter($(element));
                }

                $(element).closest('.form-group').removeClass('has-error');
                $( element ).next( "span" ).addClass( "glyphicon-ok" ).removeClass( "glyphicon-remove" );
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        function recaptchaCallback() {
          $('#hiddenRecaptcha').valid();
        }

        $('#login').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                log: {
                    required: true,
                    email: true
                },
                pwd: {
                    required: true
                }
            },
            messages: {
                log: {
                    required: 'Preencha com seu e-mail.',
                    email: 'Preencha com e-mail no formato correto'
                },
                pwd: {
                    required: 'Preencha a sua senha.',
                    maxlength: 'Tamanho máximo de 20 caracteres'
                },
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {
                if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $('#lostpassword').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                user_login: {
                    required: true,
                    email: true
                },
                hiddenRecaptcha: {
                    required: function () {
                        return grecaptcha.getResponse() == '';
                    }
                }
            },
            messages: {
                user_login: {
                    required: 'Preencha com seu e-mail.',
                    email: 'Preencha com e-mail no formato correto'
                },
                hiddenRecaptcha: {
                    required: "Valide o Captcha primeiro."
                }
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {
                if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $('#retrievepassword').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                pass1: {
                    required: true
                },
                pass2: {
                    required: true,
                    equalTo: "input[name='pass1']"
                }
            },
            messages: {
                pass1: {
                    required: 'Preencha com sua nova senha.'
                },
                pass2: {
                    required: 'Preencha com sua nova senha.',
                    equalTo: 'Senhas diferentes.'
                }
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {
                if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $('#perfil').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                pass_old: {
                    maxlength: 128
                },
                pass: {
                    maxlength: 128
                },
                pass2: {
                    equalTo: "input[name='pass']",
                    maxlength: 128
                },
                first_name: {
                    required: true,
                    maxlength: 254,
                },
                last_name: {
                    required: true,
                    maxlength: 254,
                },
                estado: {
                    required: true
                },
                municipio: {
                    required: true
                }
            },
            messages: {
                pass_old: {
                    required: 'Preencha com sua senha antiga.',
                    maxlength: 'Tamanho maximo de 128 caracteres.'
                },
                pass: {
                    required: 'Preencha a sua nova senha.',
                    maxlength: 'Tamanho maximo de 128 caracteres.'
                },
                pass2: {
                    required: 'Preencha a sua nova senha.',
                    equalTo: "Senhas diferentes",
                    maxlength: 'Tamanho maximo de 128 caracteres.'
                },
                first_name: {
                    required: 'Preencha com seu primeiro nome.',
                    maxlength: 'Tamanho maximo de 254 caracteres.'
                },
                last_name: {
                    required: 'Preencha com seu último nome.',
                    maxlength: 'Tamanho maximo de 254 caracteres.'
                },
                estado: {
                    required: 'Selecione seu estado.'
                },
                municipio: {
                    required: 'Selecione sua cidade.'
                },
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {
                if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $('#input-tags').find('input').attr('name','tags');
        $('#input-category').find('input').attr('name','category');

        $('#posting').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '[type="button"]',
            rules: {
                title: {
                    required: true
                },
                'category[]': {
                    required: true
                },
                'comunity-status[]': {
                    required: true
                }
            },
            messages: {
                title: {
                    required: 'Preencha o título.'
                },
                'category[]': {
                    required: 'Selecione uma categoria.'
                },
                'comunity-status[]': {
                    required: 'Selecione onde será publicado.'
                },
                municipio: {
                    required: 'Selecione a cidade.'

                },
                estado: {
                    required: 'Selecione o estado.'

                }


            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {
                if (element.parents(".form-checkbox").size() > 0) {
                    error.appendTo(element.parents(".form-checkbox"));
                }else if (element.parents(".ms-ctn").size() > 0) {
                    error.insertAfter(element.parents(".ms-ctn"));
                } else if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $('#contato').validate({
            errorElement: 'span',
            errorClass: 'help-block help-block-error',
            focusInvalid: true,
            focusCleanup: false,
            onkeyup: false,
            ignore: '',
            rules: {
                name: {
                    maxlength: 128,
                    required: true
                },
                email: {
                    email: true,
                    required: true
                },
                confirm_email: {
                    required: true,
                    email: true,
                    equalTo: "input[name='email']"
                },
                category: {
                    required: true
                },
                subject: {
                    maxlength: 200,
                    required: true
                },
                estado: {
                    required: true
                },
                city: {
                    required: true
                },
                message: {
                    maxlength: contact_msg_limit,
                    required: true
                },
                hiddenRecaptcha: {
                    required: function () {
                        return grecaptcha.getResponse() == '';
                    }
                }
            },
            messages: {
                name: {
                    maxlength: 'Tamanho máximo de 128 caracteres.',
                    required: 'Preencha seu nome.'
                },
                email: {
                    email: valid_mail_msg,
                    required: 'Informe seu e-mail.'
                },
                confirm_email: {
                    required: 'Confirme seu e-mail.',
                    email: valid_mail_msg,
                    equalTo: "Atenção: A confirmação do e-mail não corresponde ao e-mail informado"
                },
                category: {
                    required: 'Selecione a categoria que melhor se adequa ao seu contato!'
                },
                subject: {
                    maxlength: 'Tamanho máximo de 200 caracteres.',
                    required: 'Informe qual o assunto do contato.'
                },
                estado: {
                    required: 'Selecione seu estado.'
                },
                municipio: {
                    required: 'Selecione sua cidade.'
                },
                message: {
                    maxlength: 'Tamanho máximo de ' + contact_msg_limit + ' caracteres.',
                    required: 'Escreva sua mensagem!'
                },
                hiddenRecaptcha: {
                    required: "Valide o Captcha primeiro."
                }
            },
            invalidHandler: function (event, validator) {},
            errorPlacement: function (error, element) {

                if(!element.parent(".form-group").is(':visible')){
                    $(element).parents("form").prepend(error);
                } else if (element.parent(".input-group").size() > 0) {
                    error.insertAfter(element.parent(".input-group"));
                } else if (element.attr("data-error-container")) {
                    error.appendTo(element.attr("data-error-container"));
                } else if (element.parents('.radio-list').size() > 0) {
                    error.appendTo(element.parents('.radio-list').attr("data-error-container"));
                } else if (element.parents('.radio-inline').size() > 0) {
                    error.appendTo(element.parents('.radio-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-list').size() > 0) {
                    error.appendTo(element.parents('.checkbox-list').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parents('.checkbox-inline').size() > 0) {
                    error.appendTo(element.parents('.checkbox-inline').attr("data-error-container"));
                } else if (element.parent().find('.help-block').size() > 0) {

                } else {
                    element.parent().append(error);
                }
            },
            highlight: function (element) {
                $(element).closest('.form-group').addClass('has-error');
            },
            unhighlight: function (element) {
                $(element).closest('.form-group').removeClass('has-error');
            },
            submitHandler: function(form) {
                $(form).find('[type="submit"]').html('<i class="fa fa-spinner fa-pulse fa-1x fa-fw"></i>');
                form.submit();
            }
        });

        $.validator.addMethod("check_email_exist", function (value, element, params) {
            var retorno = false;
            var email = $("input[name='mail']").val();
            $.ajax({
                async: false,
                type: "POST",
                dataType: "json",
                url: vars.ajaxurl,
                data: {action: 'check_email_exist','email': email},
                success: function (data) {
                    if (!data) {
                        retorno = true;
                    }
                },
                error: function (data) {
                    retorno = false;
                }
            });
            return retorno;
        });

        $("body").on('click','.show_pass i',function(){

            var input = $(this).closest('.form-group').find('input');

            if($(input).attr('type') == 'text'){
                $(input).attr('type', 'password');
                $(this).removeClass().addClass('fa fa-eye-slash');
            } else {
                $(input).attr('type', 'text');
                $(this).removeClass().addClass('fa fa-eye');
            }
        });

        $('.js-add-link').click(function() {
            var links = $(this).closest('.panel-body').find('.links').last().clone();
            links.find('input').attr('value','').each(function(){
                this.name = this.name.replace(/\[(\d+)\]/, function(string,n1){return '[' + (parseInt(n1,10)+1) + ']'});
            });
            links.insertAfter($(this).closest('.panel-body').find('.links').last());
        });

        $('.remove-link').live("click", function() {
            $(this).closest('.links').remove();
        });
        
    });
    
});