jQuery( function( $ ) {

    $(function () {
        jQuery.validator.setDefaults({
            debug: true,
            focusCleanup: true
        });
        $("#form-cadastro").validate({
            rules: {
                name: {
                    required: true,
                    minlength: 9,
                    maxlength: 50
                },
                mail: {
                    required: true,
                    email: true
                },
                pass: {
                    required: true,
                    minlength: 5    
                },
                estado: {
                    required: true
                },
                municipio: {
                    required: true
                }
            },
            messages: {
                name: {
                    required: "O nome é necessário!",
                    minlength: "Insira seu nome completo!"
                },
                mail: {
                    required: "O Email é necessário!",
                    email: "Preencha corretamento seu email!"
                },
                pass: {
                    required: "A senha é necessária!",
                    minlength: "Senha deve ser acima de 5 caracteres!"
                },
                estado: {
                    required: "O Estado é Obrigatório!"
                },
                municipio: {
                    required: "A Cidade é Obrigatório!"
                }
            },
            errorContainer: ".block-email", 
            errorLabelContainer: ".block-email", 
            errorElement: "dt",
            errorPlacement: function ( error, element ) {
                // Add the `help-block` class to the error element
                error.addClass( "help-block" );

                // Add `has-feedback` class to the parent div.form-group
                // in order to add icons to inputs
                element.parents( ".col-sm-12" ).addClass( "has-feedback" );

                if ( element.prop( "type" ) === "checkbox" ) {
                    error.insertIn( element.parent( "label" ) );
                } else {
                    error.appendTo( element );
                }

                // Add the span element, if doesn't exists, and apply the icon classes to it.
                if ( !element.next( "span" )[ 0 ] ) {
                    $("<span class='glyphicon glyphicon-remove form-control-feedback'></span>").insertAfter(element);
                }
            },
            success: function ( label, element ) {
                // Add the span element, if doesn't exists, and apply the icon classes to it.
                if ( !$( element ).next( "span" )[ 0 ] ) {
                    $("<span class='glyphicon glyphicon-ok form-control-feedback'></span>").insertAfter($(element));
                }
                
            },
            highlight: function ( element, errorClass, validClass ) {
                $( element ).parents( ".col-sm-12" ).addClass( "has-error" ).removeClass( "has-success" );
                $( element ).next( "span" ).addClass( "glyphicon-remove" ).removeClass( "glyphicon-ok" );
            },
            unhighlight: function ( element, errorClass, validClass ) {
                $( element ).parents( ".col-sm-12" ).addClass( "has-success" ).removeClass( "has-error" );
                $( element ).next( "span" ).addClass( "glyphicon-ok" ).removeClass( "glyphicon-remove" );
            }
        });

        $("#show_pass").bind('click', function(){
            if($(this).is(':checked')){
                $('#pass').attr('type', 'text');
            }else{
                $('#pass').attr('type', 'password');
            }
        });

        $('.js-add-link').click(function() {
            var links = $('.add-link #Links').last().clone();
            $(links).find('input').attr('value','');
            $('.add-link').append(links);
        });

        $('#ms-filter').magicSuggest({
            placeholder: 'Tags',
            allowFreeEntries: false,
            data: [{
                id: 1,
                name: 'Tag1',
                nb: 34
            }, {
                id: 2,
                name: 'Tag2',
                nb: 106
            }],
            selectionPosition: 'inner',
            selectionStacked: true,
            mode: 'remote',
            selectionRenderer: function(data){
                return data.name + ' (<b>' + data.nb + '</b>)';
            }
        });

    });
});

function removerLink(link) {
    jQuery(link).closest('#Links').remove();
}