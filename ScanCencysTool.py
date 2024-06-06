from censys.search import CensysHosts
import json
import pandas as pd
import openpyxl
import socket
from openpyxl.styles import NamedStyle, PatternFill
from openpyxl.formatting.rule import Rule
from openpyxl.styles.differential import DifferentialStyle
from openpyxl.formatting.rule import ColorScaleRule
from openpyxl.styles import Alignment
from openpyxl.styles import Border, Side
from openpyxl import load_workbook
import re

def is_valid_ip(ip):
    # Regex pattern cho IP v4
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, ip))

def check_port(ip, port):
    # Tạo một socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)  # Thiết lập thời gian timeout

    # Thử kết nối tới cổng
    result = sock.connect_ex((ip, port))

    # Đóng kết nối
    sock.close()

    # Kiểm tra kết quả kết nối
    if result == 0:
        return 1
    else:
        return 0
# Đọc file IP


def read_ip_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Lấy thông tin từ Censys


def get_censys_info(api_id, api_secret, ip_list):
    censys = CensysHosts(api_id=api_id, api_secret=api_secret)
    extracted_data = {}
    i=1
    for ip in ip_list:
        
        if(is_valid_ip(ip)):
            print(f"censys processing for {ip}.....")
            i=i+1
        else:
            print("detected a invalid IP.")
            with open("log_err.txt",'a') as file:
                file.write(f"row {i}:{ip} -> not a valid IP\n")
                i=i+1
                continue
        try:
            data = censys.view(ip)
            domains = data.get("dns", {}).get("names", [])
            domain = ', '.join(domains)
            operating_system = data.get("operating_system", {}).get("product")
            extracted_services = []
            # Lặp qua mỗi dịch vụ và trích xuất thông tin
            for service in data.get("services", []):
                _decoded = service.get("_decoded", "")
                port = service.get("port", "")
                if (check_port(ip, port)):
                    banner = service.get("banner", "")
                transport_protocol = service.get("transport_protocol", "")
                softwares = []
                for software in service.get("software", []):
                    if software.get("product") != operating_system:
                        version = "_" + \
                            software.get("version", "") if software.get(
                                "version") else ""
                        product = f"{software.get('product', '')}{version}"
                        softwares.append(product)

                extracted_service = {
                    "port_protocol": f"{port}/{transport_protocol.upper()}(checked)",
                    "service": _decoded,
                    "product": softwares
                }
                # Thêm thông tin đã trích xuất vào danh sách dịch vụ
                extracted_services.append(extracted_service)
            # Thêm danh sách dịch vụ đã trích xuất vào dữ liệu của IP hiện tại
            extracted_data[ip] = {
                "domain": domain,
                "services": extracted_services
            }
        except Exception as e:
            extracted_data[ip] = {"error": str(e)}
    return extracted_data


def json_to_excel(json_data, output_file):
    # Đọc dữ liệu JSON thành một từ điển
    data_dict = json.loads(json_data)

    # Tạo một danh sách các DataFrame để nối lại sau này
    dfs = []

    for ip, ip_data in data_dict.items():
        domain = ip_data.get('domain', [])
        services = ip_data.get('services', [])
        for service in services:
            port_protocol = service.get('port_protocol', '')
            product = service.get('product', '')
            df = pd.DataFrame(
                {'IP': ip, 'Domain': domain, 'Port_Protocol': port_protocol, 'Product': product})
            dfs.append(df)

    # Nối tất cả các DataFrame trong danh sách lại thành một DataFrame lớn
    final_df = pd.concat(dfs, ignore_index=True)
    final_df.to_excel(output_file, index=False)


def apply_table_style(ws):
    # Tạo kiểu dữ liệu "Table" cho dữ liệu trong bảng
    table_style = NamedStyle(name="Table")
    table_style.alignment = Alignment(horizontal='center', vertical='center')

    # Thiết lập màu nền cho dữ liệu
    fill = PatternFill(start_color="F2F2F2",
                       end_color="F2F2F2", fill_type="solid")
    table_style.fill = fill


def apply_conditional_formatting(ws):
    # Tạo rule cho conditional formatting
    rule = Rule(type="expression", dxf=DifferentialStyle(fill=PatternFill(
        start_color="00FF00", end_color="00FF00", fill_type="solid")))
    rule.formula = ["TRUE"]

    # Áp dụng rule cho dữ liệu
    ws.conditional_formatting.add("A1:F1", rule)


def find_last_row(ws, column):
    for row in range(ws.max_row, 0, -1):
        cell_value = ws.cell(row=row, column=column).value
        if cell_value:
            return row
    return 1


def apply_border_to_header(ws):
    thin_border = Border(left=Side(style='thin'),
                         right=Side(style='thin'),
                         top=Side(style='thin'),
                         bottom=Side(style='thin'))

    # Áp dụng đường viền cho hàng đầu tiên từ cột A đến F
    for col in range(1, 7):  # Từ cột A đến cột F
        last_row = find_last_row(ws, col)
        for row in range(1, last_row + 1):
            ws.cell(row=row, column=col).border = thin_border


def autofit_columns(ws):
    for column in ws.columns:
        max_length = 0
        column = column[0].column_letter
        for cell in ws[column]:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = (max_length + 2) * 1.2
        ws.column_dimensions[column].width = adjusted_width


def format_excel_sheet(file_path):
    # Load workbook
    wb = load_workbook(file_path)
    ws = wb.active
    # Áp dụng kiểu dữ liệu "Table"
    apply_table_style(ws)
    # Áp dụng hiệu ứng bảng
    apply_conditional_formatting(ws)
    # Áp dụng đường viền cho các ô có giá trị (chứa chữ)
    apply_border_to_header(ws)
    autofit_columns(ws)
    # Lưu lại file
    wb.save(file_path)


def merge(input_file, output_file):
    # Load workbook
    wb = openpyxl.load_workbook(input_file)
    ws = wb.active
    # Merge cells in the first column with the same value
    current_value_col1 = None
    current_value_col2 = None
    start_row_col1 = None
    start_row_col2 = None
    end_row_col1 = None
    end_row_col2 = None

    for row in range(1, ws.max_row + 1):
        cell_value_col1 = ws.cell(row=row, column=1).value
        cell_value_col2 = ws.cell(row=row, column=2).value
        # Merge for column 1
        if cell_value_col1 == current_value_col1:
            end_row_col1 = row
        else:
            if start_row_col1 is not None and end_row_col1 is not None:
                merge_cells(ws, start_row_col1, end_row_col1, 1)
                align_cells(ws, start_row_col1, end_row_col1, 1)
            current_value_col1 = cell_value_col1
            start_row_col1 = row
            end_row_col1 = row

        # Merge for column 2
        if cell_value_col2 == current_value_col2:
            end_row_col2 = row
        else:
            if start_row_col2 is not None and end_row_col2 is not None:
                merge_cells(ws, start_row_col2, end_row_col2, 2)
                align_cells(ws, start_row_col2, end_row_col2, 2)
            current_value_col2 = cell_value_col2
            start_row_col2 = row
            end_row_col2 = row

    # Merge and align the last group of cells for column 1
    if start_row_col1 is not None and end_row_col1 is not None:
        merge_cells(ws, start_row_col1, end_row_col1, 1)
        align_cells(ws, start_row_col1, end_row_col1, 1)

    # Merge and align the last group of cells for column 2
    if start_row_col2 is not None and end_row_col2 is not None:
        merge_cells(ws, start_row_col2, end_row_col2, 2)
        align_cells(ws, start_row_col2, end_row_col2, 2)

    # Save the workbook
    ws.cell(row=1, column=ws.max_column + 1, value="Ghi chú")
    ws.cell(row=1, column=ws.max_column + 1, value="Khuyến nghị")
    wb.save(output_file)


def merge_cells(ws, start_row, end_row, column):
    ws.merge_cells(start_row=start_row, end_row=end_row,
                   start_column=column, end_column=column)


def align_cells(ws, start_row, end_row, column):
    alignment = Alignment(horizontal='center', vertical='center')
    for row in range(start_row, end_row + 1):
        ws.cell(row=row, column=column).alignment = alignment


def main(censys_api_id, censys_api_secret):
    # Nhập đường dẫn từ người dùng
    ip_file = input("Nhập đường dẫn tới file chứa danh sách IP: ")

    ip_list = read_ip_file(ip_file)

    print("Fetching data from Censys...")
    censys_info = get_censys_info(censys_api_id, censys_api_secret, ip_list)

    # Lưu dữ liệu JSON vào file JSON
    censys_info_json = json.dumps(censys_info, indent=4)

    # Chuyển đổi dữ liệu JSON thành file Excel
    json_to_excel(censys_info_json, 'output.xlsx')
    merge("output.xlsx", "output.xlsx")
    # Thực hiện định dạng cho file Excel
    format_excel_sheet("output.xlsx")


# Thay thế các giá trị sau bằng thông tin thực của bạn
CENSYS_API_ID = '882399db-2bf4-491f-88d8-7166d772ce7c'
CENSYS_API_SECRET = 'IjJiYYNkvjBGkJIqhBC8VMm71a7AK1cy'

if __name__ == "__main__":
    main(CENSYS_API_ID, CENSYS_API_SECRET)