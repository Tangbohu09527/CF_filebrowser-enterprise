"""Pure stdlib synthetic PDF/OOXML fixtures, with no plugin or host imports."""
import io
import zipfile


def pdf_fixture(*, scanned=False, encrypted=False, mixed=False):
    """A synthetic valid PDF with a real page tree, text font and xref table."""
    stream = (b"q 100 0 0 100 10 10 cm /Im1 Do Q" if scanned else
              b"BT /F1 12 Tf 20 200 Td (Quarterly revenue is 1234 USD.) Tj ET")
    resources = b"/XObject << /Im1 6 0 R >>" if scanned else b"/Font << /F1 5 0 R >>"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << " + resources + b" >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 1 >>\nstream\n\x80\nendstream"]
    if mixed:
        objects[1] = b"<< /Type /Pages /Count 2 /Kids [3 0 R 7 0 R] >>"
        scan_stream = b"q 100 0 0 100 10 10 cm /Im1 Do Q"
        objects.extend([b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Im1 6 0 R >> >> /Contents 8 0 R >>",
                        b"<< /Length " + str(len(scan_stream)).encode() + b" >>\nstream\n" + scan_stream + b"\nendstream"])
    if encrypted:
        objects.append(b"<< /Filter /Standard /V 1 /R 2 /Length 40 /O <" + b"00" * 32 +
                       b"> /U <" + b"11" * 32 + b"> /P -4 >>")
    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, item in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(f"{index} 0 obj\n".encode() + item + b"\nendobj\n")
    offset = len(document)
    document.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for start in offsets[1:]:
        document.extend(f"{start:010} 00000 n \n".encode())
    trailer = f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R".encode()
    if encrypted:
        trailer += b" /Encrypt 7 0 R /ID [<0011223344556677><0011223344556677>]"
    document.extend(trailer + f" >>\nstartxref\n{offset}\n%%EOF\n".encode())
    return bytes(document)


def office_fixture(kind, *, text="Quarterly revenue is 1234 USD.", macro=False):
    """Small OOXML packages, generated in memory; no Office application/macros."""
    package = io.BytesIO()
    types = {"docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
             "xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
             "pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml")}
    part, mime = types[kind]
    rel = "http://schemas.openxmlformats.org/package/2006/relationships"
    orel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as z:
        extra_type = ('<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' if kind == "xlsx" else
                      '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>' if kind == "pptx" else '')
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/' + part + '" ContentType="' + mime + '"/>' + extra_type + '</Types>')
        z.writestr("_rels/.rels", f'<Relationships xmlns="{rel}"><Relationship Id="rId1" Type="{orel}/officeDocument" Target="{part}"/></Relationships>')
        if kind == "docx":
            z.writestr(part, '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>' + text + '</w:t></w:r></w:p><w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p></w:body></w:document>')
        elif kind == "xlsx":
            ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
            z.writestr(part, f'<workbook xmlns="{ns}" xmlns:r="{orel}"><sheets><sheet name="Revenue" sheetId="1" r:id="rId1"/></sheets></workbook>')
            z.writestr("xl/_rels/workbook.xml.rels", f'<Relationships xmlns="{rel}"><Relationship Id="rId1" Type="{orel}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
            z.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{ns}"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{text}</t></is></c><c r="B1"><v>1234</v></c></row></sheetData></worksheet>')
        else:
            p = "http://schemas.openxmlformats.org/presentationml/2006/main"
            a = "http://schemas.openxmlformats.org/drawingml/2006/main"
            z.writestr(part, f'<p:presentation xmlns:p="{p}" xmlns:r="{orel}"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>')
            z.writestr("ppt/_rels/presentation.xml.rels", f'<Relationships xmlns="{rel}"><Relationship Id="rId1" Type="{orel}/slide" Target="slides/slide1.xml"/></Relationships>')
            z.writestr("ppt/slides/slide1.xml", f'<p:sld xmlns:p="{p}" xmlns:a="{a}"><p:cSld><p:spTree><p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>')
        if macro:
            z.writestr("word/vbaProject.bin", b"must never execute")
    return package.getvalue()


