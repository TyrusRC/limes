// Reports page: the print button (the browser's "Save as PDF" makes the file).
document.addEventListener('click', function (e) {
  if (e.target.closest('[data-rpt-print]')) window.print();
});
