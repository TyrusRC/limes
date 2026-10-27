// Asset tags on the Assets page: chips, the per-asset editor and bulk tag / untag. Needs asset.js (asset_post, asset_fetch,
// asset_project, asset_reload, asset_toast). Tag names are data: tag_esc escapes quotes too, so a name is safe in text
// and in a quoted attribute, and nothing here builds markup from a name any other way.

var TAG_ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
var TAG_BULK_MAX = 200;  // limes.tags.MAX_ASSETS

function tag_esc(v) {
	return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function(c) { return TAG_ENTITIES[c]; });
}

// Clickable chips (a chip filters the list by its tag); the filter reads the chip's text, never an attribute.
function tag_chips_html(tags) {
	return (tags || []).map(function(t) {
		return '<button type="button" class="l-tag-chip" title="Show assets with this tag">' + tag_esc(t) + '</button>';
	}).join(' ');
}

// "a, b c" -> ['a', 'b', 'c']; the server validates and normalises each name.
function tag_parse(text) {
	return String(text || '').split(/[\s,]+/).filter(function(t) { return t; });
}

function tag_can_write() {
	return document.getElementById('asset_results').dataset.canWrite === '1';
}

// Checkboxes appear for anyone who can use a bulk action (tags or rescan).
function asset_can_pick() {
	return document.getElementById('asset_results').dataset.canPick === '1';
}

// The Tags cell: chips, and a pencil that opens the editor when the user may change tags.
function tag_cell_html(row) {
	var edit = tag_can_write() ? ' <button type="button" class="l-link-btn tag_edit" data-id="' + Number(row.id) + '" aria-label="Edit tags"><i class="fe-edit-2" aria-hidden="true"></i></button>' : '';
	return tag_chips_html(row.tags) + edit;
}

function tag_load_options() {
	fetch('/api/tags/?project=' + encodeURIComponent(asset_project()), {credentials: 'same-origin'})
		.then(function(r) { return r.ok ? r.json() : []; })
		.then(function(rows) {
			var list = document.getElementById('tag_options');
			if (!list) return;
			list.replaceChildren.apply(list, rows.map(function(t) {
				var o = document.createElement('option');
				o.value = t.name;
				return o;
			}));
		}).catch(function() {});
}

function tag_submit(ids, add, remove, resultId) {
	var out = document.getElementById(resultId);
	return asset_post('/api/action/asset/tags/', {project: asset_project(), assets: ids, add: add, remove: remove}).then(function(data) {
		if (!data.status) {
			out.innerHTML = '<div class="alert alert-danger">' + tag_esc(data.message) + '</div>';
			return;
		}
		asset_toast('Tags updated.');
		$('#modal_dialog').modal('hide');
		asset_reload();
		tag_load_options();
	}).catch(function() { asset_toast('Request failed.', true); });
}

// One asset: its tags with a remove button each, and a box to add more.
function edit_asset_tags(id) {
	asset_fetch(id).then(function(a) {
		var cur = a.tags || [];
		var chips = cur.map(function(t, i) {
			return '<span class="l-tag-chip">' + tag_esc(t) + ' <button type="button" class="btn-close tag_remove" data-i="' + Number(i) + '" aria-label="Remove tag ' + tag_esc(t) + '"></button></span>';
		}).join(' ') || '<span class="l-muted">No tags yet.</span>';
		asset_modal_wide(false);
		$('#modal_title').text('Tags: ' + a.value);
		$('#modal-content').html('<div class="mb-3" id="tag_current">' + chips + '</div>' +
			'<label class="form-label" for="tag_add">Add tags (comma separated)</label>' +
			'<input type="text" id="tag_add" class="form-control mb-2" list="tag_options" maxlength="400" autocomplete="off">' +
			'<p class="l-hint">Lower case letters, digits and . _ : / - (up to 40 characters), 20 tags per asset.</p><div id="tag_result"></div>');
		$('#modal-footer').html('<button type="button" class="btn btn-primary" id="tag_save">Add</button>');
		document.getElementById('tag_save').addEventListener('click', function() {
			var add = tag_parse(document.getElementById('tag_add').value);
			if (!add.length) return;
			tag_submit([Number(id)], add, [], 'tag_result');
		});
		$('#tag_current').on('click', '.tag_remove', function() {
			tag_submit([Number(id)], [], [cur[Number(this.dataset.i)]], 'tag_result');
		});
		$('#modal_dialog').modal('show');
	}).catch(function() { asset_toast('Unable to load asset.', true); });
}

function tag_selected_ids() {
	return $('#asset_results .asset_pick:checked').map(function() { return Number(this.value); }).get();
}

function tag_bulk_refresh() {
	var n = tag_selected_ids().length, bar = document.getElementById('tag_bulk');
	if (!bar) return;
	bar.hidden = n === 0;
	document.getElementById('tag_bulk_count').textContent = n + (n === 1 ? ' asset selected' : ' assets selected');
}

// mode 'add' or 'remove' on the ticked rows of this page.
function tag_bulk_modal(mode) {
	var ids = tag_selected_ids();
	if (!ids.length) return;
	if (ids.length > TAG_BULK_MAX) { asset_toast('Select at most ' + TAG_BULK_MAX + ' assets at a time.', true); return; }
	var adding = mode === 'add';
	asset_modal_wide(false);
	$('#modal_title').text((adding ? 'Tag ' : 'Untag ') + ids.length + (ids.length === 1 ? ' asset' : ' assets'));
	$('#modal-content').html('<label class="form-label" for="tag_bulk_names">' + (adding ? 'Tags to add' : 'Tags to remove') + ' (comma separated)</label>' +
		'<input type="text" id="tag_bulk_names" class="form-control mb-2" list="tag_options" maxlength="400" autocomplete="off"><div id="tag_bulk_result"></div>');
	$('#modal-footer').html('<button type="button" class="btn btn-primary" id="tag_bulk_go">' + (adding ? 'Tag' : 'Untag') + '</button>');
	document.getElementById('tag_bulk_go').addEventListener('click', function() {
		var names = tag_parse(document.getElementById('tag_bulk_names').value);
		if (!names.length) return;
		tag_submit(ids, adding ? names : [], adding ? [] : names, 'tag_bulk_result');
	});
	$('#modal_dialog').modal('show');
}

function tag_init() {
	tag_load_options();
	var table = $('#asset_results');
	table.on('click', '.l-tag-chip', function() {
		var f = document.getElementById('f_tag');
		f.value = this.textContent;
		f.dispatchEvent(new Event('change'));
	});
	table.on('click', '.tag_edit', function() { edit_asset_tags(Number(this.dataset.id)); });
	table.on('change', '.asset_pick', tag_bulk_refresh);
	table.on('draw.dt', function() {
		var a = document.getElementById('asset_pick_all');
		if (a) a.checked = false;
		tag_bulk_refresh();
	});
	var all = document.getElementById('asset_pick_all');
	if (all) {  // only users who may change tags get the checkboxes
		all.addEventListener('click', function(e) { e.stopPropagation(); });  // not a sort click on the header
		all.addEventListener('change', function() {
			var on = this.checked;
			$('#asset_results .asset_pick').prop('checked', on);
			tag_bulk_refresh();
		});
	}
	var add = document.getElementById('tag_bulk_add'), rem = document.getElementById('tag_bulk_remove');
	if (add) add.addEventListener('click', function() { tag_bulk_modal('add'); });
	if (rem) rem.addEventListener('click', function() { tag_bulk_modal('remove'); });
}
