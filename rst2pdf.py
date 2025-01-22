import argparse
from docutils.core import publish_string
from io import BytesIO
from xhtml2pdf import pisa

def rst_to_pdf(input_file, output_file):
    # Convert RST to HTML
    with open(input_file, 'r') as file:
        rst_content = file.read()
    html_content = publish_string(source=rst_content, writer_name='html').decode('utf-8')

    # Convert HTML to PDF
    result = BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=result)

    if not pisa_status.err:
        with open(output_file, 'wb') as pdf_file:
            pdf_file.write(result.getvalue())
    else:
        raise ValueError("Failed to convert HTML to PDF. Please check the input file and dependencies.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert an RST file to PDF.")
    parser.add_argument("--infile", required=True, help="Input RST file")
    parser.add_argument("--outfile", required=True, help="Output PDF file")

    args = parser.parse_args()

    rst_to_pdf(args.infile, args.outfile)
