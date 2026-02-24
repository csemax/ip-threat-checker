/**
 * main.js - JavaScript Utama
 * Pegadaian IP Security Checker
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log('IP Security Checker initialized');

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Form loading state
    const forms = document.querySelectorAll('form[method="POST"]');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            const btn = form.querySelector('button[type="submit"]');
            if (btn && !btn.classList.contains('btn-outline-danger')) {
                btn.disabled = true;
                const originalText = btn.innerHTML;
                btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';

                // Re-enable after 60 seconds (safety)
                setTimeout(function() {
                    btn.disabled = false;
                    btn.innerHTML = originalText;
                }, 60000);
            }
        });
    });

    // IP input auto-format (remove spaces)
    const ipInputs = document.querySelectorAll('input[name="ip_address"]');
    ipInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            this.value = this.value.trim().replace(/\s+/g, '');
        });
    });
});