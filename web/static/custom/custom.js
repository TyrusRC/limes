// Helpers every page shares: CSRF cookie, HTML encoding, the create-project dialog and tab links by URL hash.

function getCookie(name) {
	var cookieValue = null;
	if (document.cookie && document.cookie !== '') {
		var cookies = document.cookie.split(';');
		for (var i = 0; i < cookies.length; i++) {
			var cookie = jQuery.trim(cookies[i]);
			// Does this cookie string begin with the name we want?
			if (cookie.substring(0, name.length + 1) === (name + '=')) {
				cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
				break;
			}
		}
	}
	return cookieValue;
}

// Source: https://portswigger.net/web-security/cross-site-scripting/preventing#encode-data-on-output
// The u flag matches whole code points, so emoji/astral characters become one valid reference, not two lone surrogates.
function htmlEncode(str) {
	return String(str).replace(/[^\w. ]/giu, function(c) {
		return '&#' + c.codePointAt(0) + ';';
	});
}

function add_project_modal(){
	Swal.fire({
		title: 'Enter the project name',
		input: 'text',
		inputAttributes: {
			autocapitalize: 'off',
			placeholder: 'Your Awesome Project'
		},
		showCancelButton: true,
		confirmButtonText: 'Create Project',
		showLoaderOnConfirm: true,
		preConfirm: (name) => {
			return fetch(`/api/action/create/project?name=${encodeURIComponent(name)}`)
				.then(response => {
					if (!response.ok) {
						throw new Error(response.error)
					}
					return response.json()
				})
				.catch(error => {
					Swal.showValidationMessage(
						`Duplicate project name, choose another project name!`
					)
				})
			},
			allowOutsideClick: () => !Swal.isLoading()
		}).then((result) => {
			if (result.isConfirmed) {
				Swal.fire({
					title: `${htmlEncode(result.value.project_name)} is created.`,
					onClose: reloadPage
				})
			}
		});
}

function reloadPage(){
	location.reload();
}

function handleHashInUrl(){
	// this function handles hash in url used to tab navigation
	const hash = window.location.hash;
	if (hash) {
		const targetId = hash.substring(1);
		const tabLink = $(`a[href="#${targetId}"][data-bs-toggle="tab"]`);
		if (tabLink.length) {
			tabLink.tab('show');
			setTimeout(() => {
				tabLink.click();
			}, 100);
		}
	}
}
