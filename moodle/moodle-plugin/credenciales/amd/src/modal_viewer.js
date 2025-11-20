define(['jquery'], function($) {
    return {
        init: function() {
            var modal = $('#certificate-modal');
            var btn = $('#view-certificate-btn');
            var closeBtn = $('.close-modal');
            var overlay = $('.modal-overlay');

            if (btn.length) {
                btn.on('click', function(e) {
                    e.preventDefault();
                    modal.removeClass('hidden');
                    // Small delay to allow display:block to apply before opacity transition
                    setTimeout(function() {
                        modal.addClass('visible');
                    }, 10);
                });
            }

            function closeModal() {
                modal.removeClass('visible');
                setTimeout(function() {
                    modal.addClass('hidden');
                }, 300);
            }

            if (closeBtn.length) {
                closeBtn.on('click', closeModal);
            }

            if (overlay.length) {
                overlay.on('click', closeModal);
            }
            
            // Close on Escape key
            $(document).on('keydown', function(e) {
                if (e.key === "Escape" && modal.hasClass('visible')) {
                    closeModal();
                }
            });
        }
    };
});
