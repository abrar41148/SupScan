import io
import zipfile
from pathlib import Path

docx = Path(r"c:\Users\Nitro\Desktop\supply-scan\submission\technical-report.docx")
buf = io.BytesIO()
with zipfile.ZipFile(docx, "r") as zin, zipfile.ZipFile(buf, "w") as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "word/numbering.xml":
            data = data.replace(
                'w:val="\u25cf"'.encode("utf-8"),
                b'w:val="&#x2022;"',
            )
        zout.writestr(item, data)
docx.write_bytes(buf.getvalue())

pptx = Path(r"c:\Users\Nitro\Desktop\supply-scan\submission\presentation.pptx")
buf = io.BytesIO()
with zipfile.ZipFile(pptx, "r") as zin, zipfile.ZipFile(buf, "w") as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "ppt/presentation.xml":
            text = data.decode("utf-8")
            start = text.find("<p:notesMasterIdLst>")
            end = text.find("</p:notesMasterIdLst>") + len("</p:notesMasterIdLst>")
            block = text[start:end]
            text = text[:start] + text[end:]
            close = "</p:sldMasterIdLst>"
            idx = text.find(close) + len(close)
            text = text[:idx] + block + text[idx:]
            data = text.encode("utf-8")
        zout.writestr(item, data)
pptx.write_bytes(buf.getvalue())
print("rewritten")
