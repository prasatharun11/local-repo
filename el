document.querySelectorAll('input[name="clm_sym_sel"]').forEach(function(input) {
    input.addEventListener('click', function() {
        loadSymbolFinData(
            this.dataset.index,
            this.dataset.clmtype,
            this.dataset.svrtind,
            this.dataset.supfinind,
            this.dataset.currcode,
            this.dataset.flagwwd
        );
    });
});