import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tldextract
from urllib.parse import urlparse
import whois
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import requests

def is_idn_homograph(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Extract the domain using tldextract
    domain_info = tldextract.extract(parsed_url.netloc)

    # Check if the domain contains non-ASCII characters (potential IDN)
    if any(ord(char) > 127 for char in domain_info.domain):
        return True
    return False

def check_url():
    url = entry.get()
    result_label.config(text="")

    # Handle different URL formats
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if is_idn_homograph(url):
        result_label.config(text=f"The URL '{url}' may be a potential IDN homograph attack.", foreground="red")
    else:
        result_label.config(text=f"The URL '{url}' appears to be genuine.", foreground="green")

def generate_pdf(whois_data, url):
    pdf_filename = f"whois_{url.replace('/', '_')}.pdf"

    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Set the title
    title = f"WHOIS information for {url}"
    title_style = styles['Title']
    story.append(Paragraph(title, title_style))

    # Set the WHOIS data
    whois_style = styles['Normal']
    for line in whois_data.split('\n'):
        story.append(Paragraph(line, whois_style))

    doc.build(story)

    return pdf_filename

def download_pdf():
    url = entry.get()

    try:
        whois_info = whois.whois(url)
        pdf_filename = generate_pdf(str(whois_info), url)
        result_text.config(state="normal")
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"WHOIS information for '{url}' has been saved to '{pdf_filename}'\n", "green")
        result_text.config(state="disabled")
    except Exception as e:
        result_text.config(state="normal")
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Failed to fetch WHOIS information for '{url}':\n", "red")
        result_text.insert(tk.END, str(e))
        result_text.config(state="disabled")

    # Open a file dialog for downloading the PDF
    file_dialog = filedialog.asksaveasfile(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if file_dialog:
        with open(pdf_filename, 'rb') as pdf_file:
            file_content = pdf_file.read()
            file_dialog.write(file_content)
        file_dialog.close()

def scan_file():
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    if file_path:
        if not api_key:
            messagebox.showerror("API Key Required", "Please provide a VirusTotal API key.")
            return

        result_text.config(state="normal")
        result_text.delete(1.0, tk.END)

        try:
            with open(file_path, "rb") as file:
                files = {"file": file}
                headers = {"x-apikey": api_key}
                response = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", headers=headers, files=files)
                if response.status_code == 200:
                    result_text.insert(tk.END, "File has been successfully submitted for scanning.\n", "green")
                else:
                    result_text.insert(tk.END, "Failed to submit the file for scanning.\n", "red")
        except Exception as e:
            result_text.insert(tk.END, f"An error occurred: {str(e)}\n", "red")

        result_text.config(state="disabled")

def upload_api_key():
    global api_key
    api_key = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if api_key:
        api_key_label.config(text="VirusTotal API Key (Uploaded)")
        messagebox.showinfo("API Key Uploaded", "VirusTotal API key has been successfully uploaded.")

# Create the main window
root = tk.Tk()
root.title("PCL Demo 1")

# Create and configure a frame
frame = ttk.Frame(root, padding=10)
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Create and configure label and entry widgets for URL check
label = ttk.Label(frame, text="Enter a URL to check:")
label.grid(row=0, column=0, sticky=tk.W)

entry = ttk.Entry(frame, width=50)
entry.grid(row=1, column=0, padx=5, pady=5)

check_button = ttk.Button(frame, text="Check URL", command=check_url)
check_button.grid(row=1, column=1, padx=5, pady=5)

result_label = ttk.Label(frame, text="", font=("Arial", 12))
result_label.grid(row=2, column=0, columnspan=2, pady=10)

# Create buttons for file scanning and downloading PDF
scan_button = ttk.Button(frame, text="Scan File with VirusTotal (Premium Feature)", command=scan_file)
scan_button.grid(row=3, column=0, columnspan=2, pady=10)

download_button = ttk.Button(frame, text="Download WHOIS PDF", command=download_pdf)
download_button.grid(row=4, column=0, columnspan=2, pady=10)

# Create and configure result text widget
result_text = tk.Text(frame, height=10, width=50, wrap=tk.WORD)
result_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
result_text.tag_configure("green", foreground="green")
result_text.tag_configure("red", foreground="red")
result_text.config(state="disabled")

# Create a button to upload VirusTotal API key (Premium Feature)
upload_api_key_button = ttk.Button(frame, text="Upload VirusTotal API Key (Premium Feature)", command=upload_api_key)
upload_api_key_button.grid(row=6, column=0, columnspan=2, pady=10)

api_key = None  # Initialize API key as None

api_key_label = ttk.Label(frame, text="VirusTotal API Key (Not Uploaded)")
api_key_label.grid(row=7, column=0, columnspan=2, pady=5)

# Start the GUI main loop
root.mainloop()
