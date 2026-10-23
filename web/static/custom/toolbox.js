function toolbox_cve_detail(){
	$('#modal_title').html('CVE Details Lookup');
	$('#modal-content').empty();
	$('#modal-content').append(`
		<div class="mb-1">
			<label for="cve_id" class="form-label">CVE ID</label>
			<input class="form-control" type="text" id="cve_id" required="" placeholder="CVE-XXXX-XXXX">
		</div>
		<div class="mt-3 mb-3 text-center">
			<button class="btn btn-primary float-end" type="submit" id="cve_detail_submit_btn">Lookup CVE</button>
		</div>
	`);
	$('#modal_dialog').modal('show');
}



$(document).on('click', '#cve_detail_submit_btn', function(){
	var cve_id = document.getElementById("cve_id").value;
	if (cve_id) {
		get_and_render_cve_details(cve_id);
	}
	else{
		swal.fire("Error!", 'Please enter CVE ID!', "warning", {
			button: "Okay",
		});
	}
});
