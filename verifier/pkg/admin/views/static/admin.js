// CCV Admin Console interactive helpers.
function copyText(btn, text) {
	if (!navigator.clipboard) {
		const ta = document.createElement("textarea");
		ta.value = text;
		document.body.appendChild(ta);
		ta.select();
		document.execCommand("copy");
		document.body.removeChild(ta);
		showCopyFeedback(btn);
		return;
	}
	navigator.clipboard.writeText(text).then(function() {
		showCopyFeedback(btn);
	});
}

function showCopyFeedback(btn) {
	const orig = btn.title;
	btn.title = "Copied!";
	btn.classList.add("copied");
	setTimeout(function() {
		btn.title = orig || "Copy to clipboard";
		btn.classList.remove("copied");
	}, 1500);
}

function toggleSelectAll(master, name) {
	const checkboxes = document.querySelectorAll('input[type="checkbox"][name="' + name + '"]:not(:disabled)');
	for (let i = 0; i < checkboxes.length; i++) {
		checkboxes[i].checked = master.checked;
	}
	master.indeterminate = false;
	updateRescheduleSelectionCount(name);
}

function updateRescheduleSelectionCount(name) {
	const enabled = document.querySelectorAll('input[type="checkbox"][name="' + name + '"]:not(:disabled)');
	let selected = 0;
	for (let i = 0; i < enabled.length; i++) {
		if (enabled[i].checked) {
			selected++;
		}
	}
	const master = document.querySelector('input[type="checkbox"][data-select-all="' + name + '"]');
	if (master && enabled.length > 0) {
		master.checked = selected === enabled.length;
		master.indeterminate = selected > 0 && selected < enabled.length;
	}
	const countEl = document.getElementById("reschedule-selected-count");
	if (countEl) {
		countEl.textContent = String(selected);
	}
	const submitBtn = document.getElementById("reschedule-submit-btn");
	if (submitBtn) {
		submitBtn.textContent = "Reschedule selected (" + selected + ")";
		submitBtn.disabled = selected === 0;
	}
}

document.addEventListener("click", function(e) {
	const btn = e.target.closest(".copy-btn[data-copy]");
	if (btn) {
		copyText(btn, btn.getAttribute("data-copy"));
	}
});

document.addEventListener("change", function(e) {
	const master = e.target.closest("input[type=\"checkbox\"][data-select-all]");
	if (master) {
		toggleSelectAll(master, master.getAttribute("data-select-all"));
		return;
	}
	const targetBox = e.target.closest("input[type=\"checkbox\"][name=\"target\"]");
	if (targetBox) {
		updateRescheduleSelectionCount("target");
	}
});

