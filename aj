// In your utility file
$.ajaxSetup({
    beforeSend: function(jqXHR, settings) {
        // This runs before each AJAX request
        console.log('Before AJAX call');
    }
});

// Override the original success/error handlers globally
var originalAjax = $.ajax;
$.ajax = function(options) {
    var originalSuccess = options.success;
    var originalError = options.error;
    var originalComplete = options.complete;
    
    // Wrap the success callback
    options.success = function(data, textStatus, jqXHR) {
        // Your common success logic first
        console.log('Common success logic executed');
        
        // Then call the original success callback if it exists
        if (typeof originalSuccess === 'function') {
            originalSuccess(data, textStatus, jqXHR);
        }
    };
    
    // Wrap the error callback
    options.error = function(jqXHR, textStatus, errorThrown) {
        // Your common error logic first
        console.log('Common error logic executed');
        
        // Then call the original error callback if it exists
        if (typeof originalError === 'function') {
            originalError(jqXHR, textStatus, errorThrown);
        }
    };
    
    // Wrap the complete callback
    options.complete = function(jqXHR, textStatus) {
        // Your common complete logic first
        console.log('Common complete logic executed');
        
        // Then call the original complete callback if it exists
        if (typeof originalComplete === 'function') {
            originalComplete(jqXHR, textStatus);
        }
    };
    
    return originalAjax.call(this, options);
};