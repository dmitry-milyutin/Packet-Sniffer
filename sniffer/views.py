
from django.conf import settings
import tempfile
from django.shortcuts import render
from .analyzer import analyze


def upload_page(request):
    if request.method != "POST" or "file" not in request.FILES:
        return render(request, "upload.html")

    upload = request.FILES["file"]

    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        for chunk in upload.chunks():
            tmp.write(chunk)
        tmp.flush()

        try:
            result = analyze(tmp.name)
        except RuntimeError as exc:
            return render(request, "upload.html", {"error": str(exc)})

    return render(request, "report.html", {
        "name": upload.name,
        "result": result,
    })