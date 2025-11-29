"""
PDF Generator Service for Security Reports

This module provides robust HTML-to-PDF conversion using wkhtmltoimage
(HTML -> Image -> PDF) for maximum stability with complex layouts.

Optimized for the pentest_report_v2.html template with print-first CSS.
"""

import logging
from pathlib import Path
from typing import Optional, Union
import asyncio
import subprocess
import tempfile
import os

logger = logging.getLogger(__name__)


class PDFGenerationError(Exception):
    """Raised when PDF generation fails"""
    pass


def html_to_pdf_wkhtmltoimage(html_content: str, quality: int = 100) -> bytes:
    """
    Convert HTML to PDF using wkhtmltoimage (HTML -> PNG -> PDF).
    
    This method provides maximum stability for complex HTML layouts by:
    1. Converting HTML to high-quality PNG using wkhtmltoimage
    2. Converting PNG to PDF using Pillow
    
    Args:
        html_content: Complete HTML document as string
        quality: Image quality 1-100 (default: 100)
        
    Returns:
        PDF content as bytes
        
    Raises:
        PDFGenerationError: If PDF generation fails
        
    Requirements:
        sudo apt install wkhtmltopdf
        pip install Pillow
    """
    try:
        from PIL import Image
    except ImportError:
        raise PDFGenerationError(
            "Pillow not installed. Run: pip install Pillow"
        )
    
    # Check if wkhtmltoimage is installed
    try:
        subprocess.run(['wkhtmltoimage', '--version'], 
                      capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise PDFGenerationError(
            "wkhtmltoimage not installed. Run: sudo apt install wkhtmltopdf"
        )
    
    try:
        logger.info("Starting PDF generation with wkhtmltoimage...")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create temp files
            html_path = os.path.join(tmpdir, 'report.html')
            png_path = os.path.join(tmpdir, 'report.png')
            pdf_path = os.path.join(tmpdir, 'report.pdf')
            
            # Step 1: Save HTML to temp file
            Path(html_path).write_text(html_content, encoding='utf-8')
            
            # Step 2: Convert HTML to PNG using wkhtmltoimage
            logger.info("Converting HTML to PNG...")
            cmd = [
                'wkhtmltoimage',
                '--quality', str(quality),
                '--width', '794',  # A4 width in pixels at 96 DPI (210mm)
                '--enable-local-file-access',
                '--quiet',
                html_path,
                png_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise PDFGenerationError(
                    f"wkhtmltoimage failed: {result.stderr}"
                )
            
            if not os.path.exists(png_path):
                raise PDFGenerationError("PNG file not created")
            
            # Step 3: Convert PNG to PDF using Pillow
            logger.info("Converting PNG to PDF...")
            img = Image.open(png_path)
            
            # Convert RGBA to RGB if necessary
            if img.mode == 'RGBA':
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[3])
                img = rgb_img
            elif img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Save as PDF
            img.save(pdf_path, 'PDF', resolution=100.0, quality=95)
            
            # Read PDF bytes
            pdf_bytes = Path(pdf_path).read_bytes()
            
            logger.info(f"✅ PDF generated successfully ({len(pdf_bytes)} bytes)")
            return pdf_bytes
            
    except Exception as e:
        logger.error(f"❌ wkhtmltoimage PDF generation failed: {e}")
        raise PDFGenerationError(f"wkhtmltoimage PDF generation failed: {str(e)}")


def html_to_pdf_playwright(html_content: str, timeout: int = 30000) -> bytes:
    """
    Convert HTML to PDF using Playwright (Chromium).
    
    This is the RECOMMENDED method for production as it provides:
    - Pixel-perfect rendering
    - Full CSS3 support (gradients, shadows, etc.)
    - Background colors and images
    - Web fonts support
    
    Args:
        html_content: Complete HTML document as string
        timeout: Page load timeout in milliseconds (default: 30000)
        
    Returns:
        PDF content as bytes
        
    Raises:
        PDFGenerationError: If PDF generation fails
        
    Requirements:
        pip install playwright
        playwright install chromium
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise PDFGenerationError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
    
    try:
        logger.info("Starting PDF generation with Playwright...")
        
        with sync_playwright() as p:
            # Launch browser in headless mode
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security'
                ]
            )
            
            # Create new page
            page = browser.new_page()
            
            # Set HTML content and wait for resources
            page.set_content(
                html_content,
                wait_until='networkidle',
                timeout=timeout
            )
            
            # Wait for fonts to load (critical for proper rendering)
            page.wait_for_load_state('networkidle')
            page.evaluate('document.fonts.ready')
            
            # Add small delay to ensure complete rendering
            page.wait_for_timeout(500)
            
            # Generate PDF with optimal settings
            pdf_bytes = page.pdf(
                format='A4',
                print_background=True,
                prefer_css_page_size=True,
                display_header_footer=False,
                margin={
                    'top': '0mm',
                    'right': '0mm',
                    'bottom': '0mm',
                    'left': '0mm'
                }
            )
            
            browser.close()
            
            logger.info(f"✅ PDF generated successfully ({len(pdf_bytes)} bytes)")
            return pdf_bytes
            
    except Exception as e:
        logger.error(f"❌ Playwright PDF generation failed: {e}")
        raise PDFGenerationError(f"Playwright PDF generation failed: {str(e)}")


async def html_to_pdf_playwright_async(html_content: str, timeout: int = 30000) -> bytes:
    """
    Async version of html_to_pdf_playwright.
    
    Use this in async contexts (FastAPI endpoints with async def).
    
    Args:
        html_content: Complete HTML document as string
        timeout: Page load timeout in milliseconds
        
    Returns:
        PDF content as bytes
        
    Example:
        ```python
        from fastapi import APIRouter
        
        @router.get("/generate-pdf")
        async def generate_pdf():
            html = render_template(...)
            pdf_bytes = await html_to_pdf_playwright_async(html)
            return Response(content=pdf_bytes, media_type="application/pdf")
        ```
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise PDFGenerationError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
    
    try:
        logger.info("Starting async PDF generation with Playwright...")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ]
            )
            
            page = await browser.new_page()
            
            await page.set_content(
                html_content,
                wait_until='networkidle',
                timeout=timeout
            )
            
            await page.wait_for_load_state('networkidle')
            await page.evaluate('document.fonts.ready')
            await page.wait_for_timeout(500)
            
            pdf_bytes = await page.pdf(
                format='A4',
                print_background=True,
                prefer_css_page_size=True,
                display_header_footer=False,
                margin={'top': '0', 'right': '0', 'bottom': '0', 'left': '0'}
            )
            
            await browser.close()
            
            logger.info(f"✅ Async PDF generated successfully ({len(pdf_bytes)} bytes)")
            return pdf_bytes
            
    except Exception as e:
        logger.error(f"❌ Async Playwright PDF generation failed: {e}")
        raise PDFGenerationError(f"Async Playwright PDF generation failed: {str(e)}")


def html_to_pdf_weasyprint(html_content: str) -> bytes:
    """
    Convert HTML to PDF using WeasyPrint (fallback option).
    
    Use this when:
    - Playwright/browser engines are not available
    - Running in restricted environments (Lambda, etc.)
    - Don't need perfect CSS3 rendering
    
    Note: WeasyPrint has limited CSS support:
    - No flexbox/grid (template uses floats as fallback)
    - Limited gradient support
    - ~85% rendering accuracy vs Playwright
    
    Args:
        html_content: Complete HTML document as string
        
    Returns:
        PDF content as bytes
        
    Requirements:
        pip install weasyprint
    """
    try:
        from weasyprint import HTML, CSS
        from io import BytesIO
    except ImportError:
        raise PDFGenerationError(
            "WeasyPrint not installed. Run: pip install weasyprint"
        )
    
    try:
        logger.info("Starting PDF generation with WeasyPrint (fallback)...")
        
        # Additional CSS for WeasyPrint compatibility
        extra_css = CSS(string='''
            @page {
                size: A4 portrait;
                margin: 0;
            }
            
            body {
                font-family: Arial, Helvetica, sans-serif;
            }
            
            .page {
                page-break-after: always;
            }
            
            .page:last-child {
                page-break-after: auto;
            }
            
            /* Force colors in PDF */
            * {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
        ''')
        
        # Generate PDF to BytesIO
        pdf_buffer = BytesIO()
        HTML(string=html_content).write_pdf(
            pdf_buffer,
            stylesheets=[extra_css]
        )
        
        pdf_bytes = pdf_buffer.getvalue()
        
        logger.info(f"✅ WeasyPrint PDF generated ({len(pdf_bytes)} bytes)")
        logger.warning("⚠️ WeasyPrint used as fallback - rendering may differ from Playwright")
        
        return pdf_bytes
        
    except Exception as e:
        logger.error(f"❌ WeasyPrint PDF generation failed: {e}")
        raise PDFGenerationError(f"WeasyPrint PDF generation failed: {str(e)}")


def html_to_pdf(
    html_content: str,
    method: str = "auto",
    timeout: int = 30000
) -> bytes:
    """
    Smart PDF generator with automatic fallback.
    
    Tries methods in order of stability:
    1. wkhtmltoimage (most stable, HTML->PNG->PDF)
    2. Playwright (high quality, requires browser)
    3. WeasyPrint (fallback, pure Python)
    
    Args:
        html_content: Complete HTML document as string
        method: "auto", "wkhtmltoimage", "playwright", or "weasyprint"
        timeout: Timeout in milliseconds (Playwright only)
        
    Returns:
        PDF content as bytes
        
    Example:
        ```python
        from jinja2 import Template
        
        # Render HTML
        template = Template(Path('templates/pentest_report_v2.html').read_text())
        html = template.render(company_name="Acme Corp", ...)
        
        # Generate PDF
        pdf_bytes = html_to_pdf(html)
        
        # Save or return
        with open('report.pdf', 'wb') as f:
            f.write(pdf_bytes)
        ```
    """
    if method == "wkhtmltoimage":
        return html_to_pdf_wkhtmltoimage(html_content)
    elif method == "playwright":
        return html_to_pdf_playwright(html_content, timeout)
    elif method == "weasyprint":
        return html_to_pdf_weasyprint(html_content)
    elif method == "auto":
        # Try wkhtmltoimage first (most stable)
        try:
            return html_to_pdf_wkhtmltoimage(html_content)
        except (ImportError, PDFGenerationError) as e:
            logger.warning(f"wkhtmltoimage unavailable ({e}), trying Playwright...")
            try:
                return html_to_pdf_playwright(html_content, timeout)
            except (ImportError, PDFGenerationError) as e2:
                logger.warning(f"Playwright unavailable ({e2}), trying WeasyPrint...")
                try:
                    return html_to_pdf_weasyprint(html_content)
                except (ImportError, PDFGenerationError) as e3:
                    logger.error(f"All PDF generation methods failed")
                    raise PDFGenerationError(
                        f"No PDF generation library available. "
                        f"Install: sudo apt install wkhtmltopdf && pip install Pillow"
                    )
    else:
        raise ValueError(f"Invalid method: {method}. Use 'auto', 'wkhtmltoimage', 'playwright', or 'weasyprint'")


def save_pdf(
    html_content: str,
    output_path: Union[str, Path],
    method: str = "auto"
) -> Path:
    """
    Generate PDF and save to file.
    
    Args:
        html_content: Complete HTML document as string
        output_path: Path where PDF will be saved
        method: "auto", "playwright", or "weasyprint"
        
    Returns:
        Path to saved PDF file
        
    Example:
        ```python
        html = "<html>...</html>"
        pdf_path = save_pdf(html, "report.pdf")
        print(f"Saved: {pdf_path}")
        ```
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    pdf_bytes = html_to_pdf(html_content, method)
    output_path.write_bytes(pdf_bytes)
    
    logger.info(f"💾 PDF saved to: {output_path}")
    return output_path


# ============================================================================
# FASTAPI INTEGRATION EXAMPLE
# ============================================================================

"""
Example integration with your FastAPI app:

```python
from fastapi import APIRouter, Response, HTTPException
from jinja2 import Template
from pathlib import Path
from app.services.pdf_generator import html_to_pdf_playwright_async

router = APIRouter()

@router.post("/generate-pentest-report")
async def generate_pentest_report(scan_data: dict):
    try:
        # Load template
        template_path = Path("app/services/templates/pentest_report_v2.html")
        template = Template(template_path.read_text())
        
        # Render HTML with data
        html_content = template.render(
            company_name=scan_data.get("client_name", "Client"),
            scan_date=scan_data.get("scan_date", "N/A"),
            devices=scan_data.get("devices", []),
            cve_vulnerabilities=scan_data.get("cves", []),
            # ... other template variables
        )
        
        # Generate PDF using wkhtmltoimage (most stable)
        pdf_bytes = html_to_pdf(html_content, method="wkhtmltoimage")
        
        # Or use async Playwright if preferred
        # pdf_bytes = await html_to_pdf_playwright_async(html_content)
        
        # Return PDF response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=pentest_report.pdf"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
```
"""


# ============================================================================
# CLI USAGE
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pdf_generator.py <html_file> [output_file] [method]")
        print()
        print("Examples:")
        print("  python pdf_generator.py report.html")
        print("  python pdf_generator.py report.html output.pdf")
        print("  python pdf_generator.py report.html output.pdf wkhtmltoimage")
        print()
        print("Methods: auto (default), wkhtmltoimage, playwright, weasyprint")
        sys.exit(1)
    
    html_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output.pdf")
    method = sys.argv[3] if len(sys.argv) > 3 else "auto"
    
    if not html_file.exists():
        print(f"❌ Error: File not found: {html_file}")
        sys.exit(1)
    
    try:
        html_content = html_file.read_text(encoding='utf-8')
        pdf_path = save_pdf(html_content, output_file, method)
        print(f"✅ Success! PDF saved to: {pdf_path}")
        print(f"📊 File size: {pdf_path.stat().st_size / 1024:.1f} KB")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

