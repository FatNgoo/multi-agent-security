# Lab máy thật: tạo hành vi, thu log và điều tra Persistence–C2

Hướng dẫn này dùng **hoạt động phát sinh trên Windows và lưu lượng đi qua mạng thật**.
Log không được tạo bằng `generate_demo`, không sửa timestamp và không chèn nhãn tấn công
vào bản ghi. Hành vi được tạo có chủ đích để kiểm thử: ghi một Run Key đánh dấu đăng nhập
và gửi HTTP định kỳ tới máy do bạn quản lý. Đây là **log thật của mô phỏng lành tính**,
không phải bằng chứng đã có malware hay một cuộc xâm nhập thật.

Các bước dưới đây chưa được tự chạy trên endpoint của bạn. Chỉ bắt đầu khi đã bố trí
máy lab; kết quả kỳ vọng là tiêu chí đối chiếu, không phải kết quả đo sẵn.

Để kiểm tra nhanh đường đi của **một kết nối HTTP** từ máy Windows tới dashboard, xem [hướng dẫn xuất và đối chiếu từng bản ghi](DOI_CHIEU_LOG.md).

## 1. Bạn sẽ quan sát được gì?

Sau một lượt hoàn chỉnh, bạn có thể đối chiếu bốn nguồn độc lập:

1. `scenario.json`: bạn đã yêu cầu máy thực hiện gì, lúc nào, có lỗi hay không.
2. Sysmon: tiến trình nào ghi registry và mở kết nối, với `ProcessGuid` nào.
3. PCAP và Zeek: kết nối thực sự đi qua mạng, IP/cổng/thời điểm và HTTP request.
4. Hệ thống: dataset, finding, evidence, liên kết, severity và báo cáo phân tích.

PCAP, EVTX và metadata được giữ nguyên để kiểm chứng lại. XML và Zeek JSON là đầu vào
ứng dụng. Không thay EVTX bằng JSON xuất tùy ý từ Event Viewer: backend có parser XML
Sysmon riêng, còn JSON Sysmon của ứng dụng dùng một schema khác.

## 2. Bố trí máy và mạng

### Phương án hai máy, ít thiết bị nhất

| Máy | Hệ điều hành/vai trò | IP mạng lab ví dụ | Công cụ |
|---|---|---|---|
| W | Windows endpoint phát sinh hành vi | `192.168.56.10/24` | Sysmon, PowerShell |
| L | Linux nhận HTTP và ghi gói tin | `192.168.56.20/24` | Python 3, tcpdump, Docker chạy Zeek |
| A | Máy phân tích; có thể chính là W hoặc máy thứ ba | Không bắt buộc cùng subnet | Dự án này, Docker Desktop |

```text
Windows W (.10) -- Ethernet/switch hoặc mạng VM riêng -- Linux L (.20)
    Sysmon                                            HTTP server + tcpdump
       |                                                   |
       +---- EVTX/XML ----> Máy A <---- PCAP/Zeek logs ------+
                               |
                       Upload và điều tra
```

Linux là **đích của HTTP**, nên card mạng Linux nhìn thấy chính lưu lượng cần thu;
không cần cấu hình SPAN cho mô hình này. Một máy Linux thứ ba chỉ cắm vào switch thông
thường sẽ không tự nhìn thấy toàn bộ unicast giữa hai máy khác.

Máy W/L có thể là hai máy vật lý hoặc hai VM chạy hệ điều hành thật. Để dùng hai máy vật
lý: nối cùng switch lab hoặc cáp Ethernet, cấu hình IPv4 tĩnh trong adapter lab. Với VM:
dùng cùng một host-only/internal network; không chọn hai NAT riêng biệt. Hai địa chỉ ở
trên chỉ là ví dụ: đổi toàn bộ lệnh nếu mạng của bạn khác. Không gán trùng IP đang dùng.

Trên Windows: mở `ncpa.cpl` → adapter lab → Properties → IPv4, đặt `.10`, subnet mask
`255.255.255.0`. Trên Linux dùng Network Settings → IPv4 Manual, đặt `.20/24`.
Adapter lab không cần default gateway. Internet để cài công cụ có thể qua adapter khác;
sau khi chuẩn bị xong, chỉ tạo lưu lượng thử tới IP lab. Giữ firewall và phần mềm bảo vệ
đang hoạt động, chỉ mở đúng cổng cần dùng.

Ứng dụng hiện bind `127.0.0.1:8000/8501`. Chạy upload trên máy A sau khi chuyển log về A;
trình duyệt trên W không thể dùng `localhost` để tới ứng dụng nằm trên máy A khác.
Không cần mở ứng dụng ra toàn mạng để làm lab này.

### Tài nguyên và quyền

- Windows 10/11 hoặc Windows Server còn dùng được với Sysmon bạn cài; dùng tài khoản lab.
- Linux có Python 3 và Docker; dành tối thiểu vài GB đĩa cho PCAP, theo dõi dung lượng.
- Quyền Administrator để cài Sysmon và đọc/export channel nếu hệ thống yêu cầu.
- Tạo Run Key HKCU bằng chính tài khoản lab; không cần thay đổi quyền hệ thống cho bước này.
- Giữ bản cấu hình Sysmon cũ trước khi thay đổi. Nếu máy đã thuộc hệ thống giám sát của
  tổ chức, dùng endpoint lab riêng thay vì ghi đè cấu hình đang vận hành.

## 3. Chuẩn bị công cụ, địa chỉ và đồng hồ

### Windows W

Copy thư mục `verification/lab/` của repo sang `C:\SecurityLab\tools\`. Kết quả cần có:

```text
C:\SecurityLab\tools\
  sysmon-lab.xml
  Invoke-LabScenario.ps1
  Export-LabLogs.ps1
```

Trong PowerShell:

```powershell
Get-NetIPConfiguration
hostname
[DateTime]::UtcNow.ToString('o')
w32tm /query /status
Test-Connection 192.168.56.20 -Count 2
```

Ping có thể bị chặn trong khi TCP vẫn chạy; kiểm tra cổng HTTP sau khi khởi động server.

### Linux L

Ví dụ Debian/Ubuntu, cài công cụ thông thường:

```bash
sudo apt update
sudo apt install python3 tcpdump jq
ip -br addr
ip route get 192.168.56.10
date -u --iso-8601=ns
timedatectl status
docker version
docker pull zeek/zeek:lts
docker run --rm zeek/zeek:lts zeek --version
docker image inspect zeek/zeek:lts --format '{{index .RepoDigests 0}}'
```

Nếu chưa có Docker, cài theo [Docker Engine cho Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
hoặc hướng dẫn đúng distro. Các lệnh Docker ở đây giả định tài khoản đã có quyền dùng
daemon; nếu chưa, dùng `sudo docker` nhất quán. Ghi lại phiên bản và digest vào biên bản
lab vì tag `lts` có thể thay đổi. Zeek cung cấp image chính thức và cũng có gói Linux;
guide này dùng Docker để tránh phụ thuộc tên package từng distro.
[Nguồn cài Zeek](https://docs.zeek.org/en/current/install.html).

Đồng bộ W và L với **cùng nguồn thời gian** trước khi ngắt Internet; mạng cô lập hoàn
toàn cần nguồn NTP nội bộ. Không chỉ so sánh giờ hiển thị: ghi offset, nguồn đồng bộ và
trạng thái trước mỗi ca. Nếu chưa xác nhận sai lệch dưới 2 giây, vẫn thu log được nhưng
không coi việc thiếu tương quan mạnh là lỗi detector. Không sửa timestamp log để ép khớp.

Nếu các máy đã cấu hình nguồn thời gian hợp lệ, có thể yêu cầu đồng bộ lại trước ca:

```powershell
# Windows Administrator; sử dụng nguồn đã cấu hình của máy
w32tm /resync
w32tm /query /source
w32tm /query /status
# Thay NTP-SERVER-CUA-LAB bằng tên/IP nguồn thật, không chạy nguyên placeholder
w32tm /stripchart /computer:NTP-SERVER-CUA-LAB /samples:5 /dataonly
```

```bash
# Linux dùng systemd-timesyncd; nếu máy dùng chrony thì xem chronyc tracking/sources
sudo timedatectl set-ntp true
timedatectl timesync-status
```

Nếu báo không có nguồn hoặc chưa synchronized, giải quyết trước khi đo chênh thời gian
cross-source. Ghi kết quả đồng bộ vào notes của ca; không dùng lệnh chỉnh giờ thủ công
giữa lúc đang thu.
Tham khảo [Windows Time Service](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)
và [timedatectl](https://www.freedesktop.org/software/systemd/man/latest/timedatectl.html).

## 4. Cài và kiểm tra Sysmon

Tải từ [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
giải nén vào `C:\SecurityLab\Sysmon\`. Trong PowerShell Administrator:

```powershell
Get-AuthenticodeSignature C:\SecurityLab\Sysmon\Sysmon64.exe |
    Select-Object Status, SignerCertificate
Get-Service '*Sysmon*' -ErrorAction SilentlyContinue
```

Chỉ dùng binary có chữ ký hợp lệ từ Microsoft. Bản Windows mới có thể có Sysmon tích
hợp; nếu đã có service, xác định bản đang dùng trước, không cài chồng hai bản.

Với endpoint lab **chưa có Sysmon**:

```powershell
C:\SecurityLab\Sysmon\Sysmon64.exe -accepteula -i C:\SecurityLab\tools\sysmon-lab.xml
```

Với bản Sysinternals **đã cài**, sau khi giữ cấu hình gốc:

```powershell
C:\SecurityLab\Sysmon\Sysmon64.exe -c C:\SecurityLab\tools\sysmon-lab.xml
C:\SecurityLab\Sysmon\Sysmon64.exe -c
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
    Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes
```

File mẫu chỉ dành cho lab, bật các nhóm process/network/file/registry/DNS khá rộng.
Schema `4.82` là phiên bản cấu hình, không phải phiên bản binary. Nếu công cụ không nhận
schema, xem `Sysmon64.exe -? config` và `Sysmon64.exe -s`, điều chỉnh theo bản đã cài và
xác nhận lệnh cài/cập nhật thành công. Không tiếp tục nếu cấu hình bị từ chối.

Event ID 3 cần được bật rõ; việc thấy process event không chứng minh đã thu network
event. Khi làm lab ngắn, cần quan sát chủ yếu ID 1, 3, 13; các ID khác bổ trợ.
[Mô tả sự kiện và cấu hình Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

Mở Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon →
Operational. Chạy một PowerShell mới, xem có Event 1 tương ứng. Chưa có log thì xử lý
khâu thu trước, không vội phân tích trên ứng dụng.

## 5. Khởi động HTTP server lành tính trên Linux

Terminal L1:

```bash
mkdir -p "$HOME/security-lab/www"
printf 'SECURITY_LAB_HEARTBEAT_OK\n' > "$HOME/security-lab/www/heartbeat.txt"
sudo python3 -u -m http.server 80 --bind 192.168.56.20 \
  --directory "$HOME/security-lab/www" 2>&1 | tee "$HOME/security-lab/http-server.log"
```

Đây là server chỉ phục vụ file thử; không nhận lệnh từ client và không triển khai shell.
Giữ terminal này mở. Nếu cổng 80 đã được sử dụng, kiểm tra `sudo ss -ltnp` và chọn cổng
khác cho toàn bộ bước capture/client/Zeek; cách đơn giản nhất cho lab mới là dùng máy
không có web server khác.

Nếu UFW đang bật, thêm luật hẹp trên đúng interface lab, ví dụ `enp0s8`:

```bash
sudo ufw status
sudo ufw allow in on enp0s8 from 192.168.56.10 to 192.168.56.20 port 80 proto tcp
```

Đổi `enp0s8` theo `ip -br addr`; không tắt firewall toàn bộ. Trên Windows:

```powershell
Test-NetConnection 192.168.56.20 -Port 80
curl.exe --noproxy '*' http://192.168.56.20/heartbeat.txt
```

Phải thấy `TcpTestSucceeded: True` và `SECURITY_LAB_HEARTBEAT_OK`.
Làm các thử kết nối này **trước cửa sổ ca chính** để tránh thêm một kết nối vào chuỗi.

## 6. Bắt PCAP và lưu bằng chứng gốc

Chọn mã ca duy nhất, ví dụ `combined-01`. Trên Linux terminal L2:

```bash
CASE=combined-01
IFACE=enp0s8
CASE_DIR="$HOME/security-lab/cases/$CASE"
mkdir -p "$CASE_DIR/pcap" "$CASE_DIR/zeek"
date -u --iso-8601=ns | tee "$CASE_DIR/capture-start-utc.txt"
sudo tcpdump -i "$IFACE" -nn -s 0 -U \
  -w "$CASE_DIR/pcap/traffic.pcap" \
  'host 192.168.56.10 and host 192.168.56.20 and (tcp port 80 or udp port 53 or tcp port 53)'
```

Capture trước khi chạy kịch bản, giữ terminal này mở. Dùng interface có route tới W,
không dùng `lo`, không capture adapter NAT nhầm. Không tạo hai PCAP ghi cùng đường dẫn.
Bộ lọc chỉ lấy trao đổi giữa hai máy lab. DNS trong phần mở rộng dùng chính Linux làm
resolver nên cũng nằm trong filter này.

Bạn có thể dùng live Zeek để quan sát, nhưng **quy trình chính là PCAP → Zeek offline**:
dễ giữ bản gốc và xử lý lại. Nếu dùng Zeek native để live, chạy trong thư mục ca riêng:

```bash
sudo zeek -i enp0s8 -C LogAscii::use_json=T
```

`-C` bỏ qua kiểm tra checksum, hữu ích khi capture trên host có checksum offloading;
ghi lại việc dùng cờ này trong biên bản. Không dùng live/offline chung thư mục đầu ra.
[Zeek Quick Start](https://docs.zeek.org/en/current/quickstart.html).

## 7. Chạy ca chính trên Windows

Mở PowerShell bằng **tài khoản lab bạn muốn ghi HKCU**, chạy một process mới:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\SecurityLab\tools\Invoke-LabScenario.ps1 `
  -Scenario Combined -ServerIp 192.168.56.20 -CaseId combined-01
```

`RemoteSigned` chỉ áp dụng cho process này; không thay chính sách toàn máy. Nếu tổ chức
bắt buộc script ký số, dùng quy trình ký/phê duyệt của máy, không hạ policy. Xem nội dung
script trước khi chạy; không dot-source vào phiên PowerShell đang sử dụng lâu dài.

Script sẽ:

1. Tạo `C:\SecurityLab\cases\combined-01\` và từ chối ghi đè ca đã có.
2. Tạo đúng một value `SecurityLabMarker` trong HKCU Run. Value chỉ gọi `cmd.exe` ghi
   timestamp vào `logon-marker.txt` khi đăng nhập lại; không tự chạy chương trình mạng.
3. Ngay trong **cùng process PowerShell**, gửi 12 HTTP request, mỗi request mở TCP mới,
   lịch gửi mặc định cách nhau 15 giây, tổng khoảng 165 giây cộng thời gian xử lý.
4. Ghi giờ UTC, PID, lịch request, status/error và phạm vi ca vào `scenario.json`.

Microsoft mô tả cơ chế đăng nhập của các key này trong
[Run và RunOnce](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).

Request chỉ có mã ca và sequence. Không gửi tài liệu, mật khẩu hoặc dữ liệu cá nhân;
không tải/chạy nội dung trả về. Không có điều khiển từ xa hay chức năng đánh cắp dữ liệu.
Nếu request thất bại, script lưu manifest rồi báo lỗi; đừng coi ca đó là ca thành công.

### Vì sao dùng cùng process?

Trong `product/app/tools/correlation.py`, tương quan mạnh hiện yêu cầu:

- Registry evidence và Sysmon Event 3 cùng host, cùng `ProcessGuid`.
- Event 3 và Zeek `conn.log` khớp source IP, source port, destination IP,
  destination port và protocol.
- Chênh timestamp không quá 2 giây.

Nếu dùng `reg.exe` để ghi Run Key rồi dùng `curl.exe` mở HTTP, hai process khác GUID;
hệ thống có thể chỉ đưa ra liên kết thời gian dạng `hypothesis`. Đó là giới hạn cách nối
hiện tại, không phải bằng chứng rằng log mạng bị mất.

### Quan sát trong lúc chạy

Ở Linux L1, nhìn các GET có `case=combined-01`, `seq=0..11`. Ở Windows mở Event Viewer,
lọc ID 13 và 3, xem XML:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3,13
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 30 | Select-Object TimeCreated, Id, MachineName, Message
```

Registry target thường hiện dưới `HKU\<SID>\Software\...\Run\SecurityLabMarker`, không
nhất thiết là chữ HKCU. Network event cần có IP `.10` → `.20`, destination port 80,
protocol TCP. Lấy GUID từ XML thật, không suy diễn chỉ từ tên `powershell.exe`.

## 8. Kết thúc thu và tạo Zeek logs

Khi Windows chạy xong, chờ khoảng 10 giây rồi bấm **Ctrl+C tại terminal tcpdump L2**.
Ghi số packet captured/dropped mà tcpdump báo; nếu có drop, ghi vào hạn chế của ca.
Không dùng `kill -9` làm bước kết thúc mặc định.

Ở Linux, trong terminal có biến ca ở bước 6 hoặc khai báo lại:

```bash
CASE=combined-01
CASE_DIR="$HOME/security-lab/cases/$CASE"
date -u --iso-8601=ns > "$CASE_DIR/capture-end-utc.txt"
sudo chown "$(id -u):$(id -g)" "$CASE_DIR/pcap/traffic.pcap"
tcpdump -nn -r "$CASE_DIR/pcap/traffic.pcap" -c 10
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$CASE_DIR:/work" -w /work/zeek \
  zeek/zeek:lts zeek -C -r /work/pcap/traffic.pcap LogAscii::use_json=T
ls -lh "$CASE_DIR/zeek"
```

Thư mục `zeek/` phải mới/trống cho lần xử lý đầu. Khi xử lý lại, tạo thư mục mới để
không lẫn output của bản Zeek khác. Không chạy lại capture chỉ để thay các log gốc.

Kỳ vọng có `conn.log` và `http.log`; không có truy vấn DNS thì **không bắt buộc có
`dns.log`**. JSON Zeek là mỗi dòng một object, không phải mảng JSON.

Kiểm tra nhanh:

```bash
jq -c 'select(."id.orig_h"=="192.168.56.10" and ."id.resp_p"==80) |
  {ts,uid,src:."id.orig_h",sport:."id.orig_p",dst:."id.resp_h",dport:."id.resp_p",proto,service,conn_state}' \
  "$CASE_DIR/zeek/conn.log"
jq -c '{ts,uid,method,uri,status_code,user_agent}' "$CASE_DIR/zeek/http.log"
sha256sum "$CASE_DIR/pcap/traffic.pcap" "$CASE_DIR"/zeek/*.log > "$CASE_DIR/linux-sha256.txt"
```

Zeek `uid` giúp nối conn và HTTP của cùng kết nối, còn source port thay đổi giữa các
lần mở TCP. Xem [tài liệu conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html).
Hệ thống hiện có tiêu chí riêng để nối Sysmon với conn; việc hai log Zeek cùng UID
không tự chứng minh process Windows nào tạo chúng.

## 9. Export Sysmon, giữ EVTX và chia XML theo giới hạn upload

Trên Windows cùng endpoint, PowerShell có quyền đọc channel:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\SecurityLab\tools\Export-LabLogs.ps1 `
  -CaseDirectory C:\SecurityLab\cases\combined-01
Get-Content C:\SecurityLab\cases\combined-01\sysmon\collection.json
```

Script chờ 15 giây cho log được chuyển tới channel, truy vấn đúng cửa sổ từ manifest,
giữ `sysmon-original.evtx`, và xuất XML gốc của các Event 1/3/11/12/13/14/22. Mỗi phần
XML khoảng dưới 4 MB để đáp ứng giới hạn upload mặc định 5.000.000 byte. Không cắt XML
bằng chia dòng tùy ý: phải giữ `<Events> ... </Events>` hợp lệ cho từng file.

`collection.json` ghi tên máy thực tế và số event. Tên `<Computer>` có thể là FQDN như
`WIN-LAB-01.lab.local`; đây mới là tên dùng trong bộ lọc điều tra. `host_hint` trong
manifest chỉ là gợi ý, không thay thế tên trong log.

EVTX dùng để lưu trữ/đọc lại bằng Event Viewer. **Không upload EVTX vào ứng dụng hiện
tại**; chọn `sysmon-001.xml`, `sysmon-002.xml`... và source `sysmon`.
Nguồn lệnh: [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
và [wevtutil export-log](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

Nếu không có quyền export, chạy lại exporter bằng Administrator với chính đường dẫn
ca cũ; script không đọc HKCU để lấy bằng chứng nên việc export không đổi tài khoản tạo
Run Key. Nếu đã có thư mục `sysmon/` từ lần export dở, giữ lại dưới tên backup rồi mới
export lại; không ghi đè bằng chứng âm thầm.

## 10. Chuyển về máy A và kiểm tra đầu vào

Tạo thư mục trong repo trên máy phân tích:

```text
verification/logs/captures/combined-01/
  scenario.json                    # Từ Windows
  sysmon/                          # Từ Windows
    sysmon-original.evtx
    sysmon-001.xml
    collection.json
    sha256.csv
  pcap/traffic.pcap                 # Từ Linux
  zeek/conn.log
  zeek/http.log
  linux-sha256.txt
  capture-start-utc.txt
  capture-end-utc.txt
```

Chuyển bằng USB/thư mục chia sẻ hoặc SCP trên kênh bạn quản lý. Nếu dùng USB, copy trước
và so SHA-256 với danh sách gốc. Không mang `.env` hoặc API key vào gói bằng chứng.

Ví dụ dùng SCP nếu Linux đã bật SSH và bạn đã xác minh host key; thay user:

```powershell
# Từ thư mục gốc repo trên máy A
New-Item -ItemType Directory -Force verification\logs\captures\combined-01 | Out-Null
scp -r labuser@192.168.56.20:/home/labuser/security-lab/cases/combined-01/zeek `
  verification/logs/captures/combined-01/
```

Copy nốt PCAP, hash, metadata và thư mục Sysmon; `scp` ở trên chỉ là ví dụ một phần.
Địa chỉ `.20` chỉ dùng được khi máy A có route tới mạng lab.

Kiểm tra parser, dung lượng và khoảng thời gian mà chưa upload:

```powershell
# Từ root repository; dùng môi trường verification đã cài dependencies
Set-Location verification
..\.venv\Scripts\python.exe -m scripts.validate_lab_capture logs/captures/combined-01
```

Lệnh chỉ đọc file, không tạo sự kiện, không gọi provider. Xem `sysmon_hosts`, event ID,
số record trong cửa sổ ca và SHA-256. Parse thành công chưa bảo đảm capture đủ gói.
Nếu Zeek file lớn hơn 5 MB, giữ file gốc, chia bản JSONL thành các phần dưới 4 MB ở
ranh giới dòng, đặt tên `conn-001.log`/`http-001.log`. Đừng upload cả bản gốc và phần
đã chia vì sẽ đếm lặp. XML chia bằng exporter. Một investigation tối đa 20 dataset;
nếu ca quá lớn, thu cửa sổ ngắn hơn hoặc chia thành các investigation có phạm vi rõ.

Thư mục artifacts đã được Git bỏ qua. Giữ một bản bằng chứng riêng ngoài thư mục làm
việc nếu cần lưu dài hạn; `.gitignore` không phải cơ chế backup.

## 11. Upload và điều tra bằng giao diện

Trên máy A, từ root repo:

```powershell
Set-Location product
docker compose up --build -d
Invoke-RestMethod http://127.0.0.1:8000/health
```

Mở `http://localhost:8501`.

### Upload

Vào **Nhập log**, chọn các tệp, đối chiếu nguồn và SHA-256 trong bảng xem trước rồi bấm **Lưu**.

| File | Source |
|---|---|
| `sysmon/sysmon-*.xml` | `sysmon` |
| `zeek/conn.log` hoặc các phần `conn-*.log` | `zeek_conn` |
| `zeek/http.log` | `zeek_http` |
| `zeek/dns.log`, nếu thực sự có | `zeek_dns` |

Không upload `traffic.pcap`, EVTX, `scenario.json` hoặc `collection.json` như log đầu
vào. Lưu dataset UUID trả về hoặc chụp lại metadata. Không chọn dataset demo cũ cho ca
này. Giao diện dùng lại dataset nếu tệp có cùng SHA-256 và nguồn. Hãy chọn một bản nếu nhiều tệp khác hash chứa cùng sự kiện.

### Phạm vi điều tra

Vào **Phân tích**, mở **Phạm vi và tùy chọn** khi cần nhập host/IP và thời gian:

1. Chỉ chọn dataset của ca `combined-01`.
2. Lấy `start_utc`/`end_utc` từ `scenario.json`. Form dùng UTC; không nhập giờ địa phương
   Việt Nam/Thái Lan mà quên chuyển UTC. Ví dụ 14:00 UTC+7 tương ứng 07:00Z.
3. Host lấy chính xác từ `sysmon/collection.json`, IP là `192.168.56.10`.
4. Xác nhận host và IP thuộc cùng thiết bị trong khoảng ca. Nếu nhập mapping bổ sung,
   dùng tên máy và thời gian thật, không copy host/time của demo tháng 10.
5. Dùng mức quan trọng tài sản `medium` cho lần đối chứng đầu, nếu giao diện có tùy chọn.
6. Chọn mode `offline` trước. Mode này **phân tích log thật** bằng pipeline deterministic,
   chỉ không gọi LLM. Nó không thay log của bạn bằng dữ liệu giả.
7. Bấm **Phân tích log**, lưu investigation UUID, trạng thái kết thúc và các cảnh báo coverage.

Mapping mẫu, **thay thời gian và host trước khi dùng**:

```json
[
  {
    "host": "TEN-MAY-TU-COLLECTION.JSON",
    "ip": "192.168.56.10",
    "start_time": "2026-11-17T07:00:00Z",
    "end_time": "2026-11-17T07:04:00Z"
  }
]
```

Nếu sai host/time, một điều tra trả ít evidence không thể dùng để đánh giá detector.
Nếu có coverage/truncation, xem giới hạn `MAX_RECORDS` ở `product/.env` trước khi kết luận
bỏ sót. Mặc định 1.000 record có thể hết nhanh với Sysmon ghi rộng. Thu ca ngắn trước,
chỉ tăng giới hạn trong miền cho phép khi có lý do; thay `.env` cần tạo lại API container.

## 12. Đối chiếu bằng chứng và kết quả kỳ vọng

### Kiểm tra theo thứ tự

| Mục quan sát | Bằng chứng cần mở | Diễn giải đúng |
|---|---|---|
| Run Key | Event 13, TargetObject kết thúc `Run\SecurityLabMarker` | Có cấu hình autorun; chưa chứng minh đã thực thi |
| Process | Event 1, Image/CommandLine/ProcessGuid | Xác định process chạy script lab |
| Network endpoint | Event 3, ProcessGuid và 5-tuple | Process đó có kết nối tới server lab |
| Network sensor | conn.log, cùng tuple, timestamp | Sensor nhìn thấy kết nối tương ứng |
| HTTP | http.log cùng Zeek UID | GET heartbeat, sequence và status thực tế |
| Periodicity | count, mean interval, CV trong finding | Tính đều của kết nối, không phải nhãn malware |
| Cross-source link | `supported_correlation` và evidence IDs | Liên hệ process–network được hỗ trợ bởi log |

Với mặc định hiện tại, detector periodic cần ít nhất **6 kết nối**, CV khoảng cách giữa
các lần bắt đầu kết nối **≤ 0,15**. Lab chính gửi 12 request ở lịch 15 giây để có dư mẫu.
CV thấp là dấu hiệu chu kỳ; dịch vụ monitoring cũng có dấu hiệu này.

Đọc **Nhận định**, sau đó mở **Bằng chứng** để xem diễn biến, liên kết Sysmon và Zeek cùng hoạt động AI. Mục **Báo cáo** cho tải kết quả.
Kiểm tra các evidence ID thật sự trỏ tới file/dòng đã upload. So sánh timestamp raw và
normalized, destination và source port; không chỉ nhìn nhãn màu.

Ca Combined hoàn chỉnh có thể tạo `run_key`, `periodic_connection` và
`supported_correlation`. Khi liên kết mạnh giao với finding network dạng hypothesis,
rubric có thể nâng triage lên High. **Không cam kết High cho mọi máy**: thiếu Event 3,
sai đồng hồ, scope bị cắt hoặc jitter cao sẽ làm kết quả khác.

### Kiểm tra giới hạn mà ca này chưa chứng minh

- Script ghi Run Key và kết nối ngay bằng process tạo key. Nó chưa chứng minh chương
  trình autorun được khởi chạy rồi trở thành process tạo network.
- Nếu đăng xuất/đăng nhập lại để xem marker, đó là lượt kiểm tra khác, cần cửa sổ thu
  riêng; marker là `cmd.exe` mới, không có GUID của process PowerShell ban đầu.
- Không có payload độc hại, nhận lệnh, exfiltration hay reputation độc hại ở đây.
- Finding C2 là giả thuyết hành vi. Kết luận “máy bị chiếm quyền” từ ca này là quá mức.
- Analyzer hiện không tự xác minh mọi quan hệ cha–con của autorun target để thay cho
  điều kiện cùng GUID. Giữ giới hạn này trong báo cáo nghiên cứu.

## 13. Các ca đối chứng nên chạy thêm

Mỗi ca dùng mã mới, PCAP mới, export Sysmon riêng. Dọn `SecurityLabMarker` trước ca có
persistence tiếp theo; không chạy chồng ca và không dùng chung dataset đầu vào.

| Ca | Tham số script | Kỳ vọng chính | Điều cần tránh suy diễn |
|---|---|---|---|
| P | `-Scenario PersistenceOnly` | Run Key; không có chuỗi HTTP do script gửi | Không tự kết luận C2 |
| N | `-Scenario PeriodicOnly` | Periodic network; không có Run Key do script tạo | Không tự kết luận persistence |
| PN | `-Scenario Combined` | Hai dấu hiệu và khả năng nối mạnh | Không gọi đây là malware thật |
| J | `-Scenario Jitter` | GET thật nhưng khoảng cách biến thiên lớn | Không ép có finding periodic |
| B | Dùng dataset N, điều tra lại với benign destination `.20` | Network có thể thành `benign_possible`, ưu tiên thấp hơn | Không sửa log gốc để hạ nhãn |
| M | Dùng PN, chỉ chọn Sysmon hoặc chỉ Zeek | Nêu thiếu nguồn; không đủ cross-source proof | Không tạo evidence còn thiếu |
| T | Dùng PN, bỏ mapping hoặc đặt scope sai có chủ đích | Cho thấy ảnh hưởng scope/mapping | Ghi rõ đây là ca thử cấu hình sai |

Các lệnh ví dụ trên Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\SecurityLab\tools\Invoke-LabScenario.ps1 -Scenario PersistenceOnly -CaseId persistence-01
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\SecurityLab\tools\Invoke-LabScenario.ps1 -Scenario PeriodicOnly -CaseId periodic-01
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\SecurityLab\tools\Invoke-LabScenario.ps1 -Scenario Jitter -CaseId jitter-01
```

Jitter dùng lịch khoảng cách 5/30/7/45/... giây, tổng thời gian dài hơn ca chuẩn; thu tới
khi script kết thúc. Không dùng số lượng request UI hiển thị để thay số connection thật:
retry, request thử ngoài ca, hoặc capture thiếu đều làm chênh số lượng.

Ca B: nếu UI chưa có trường `benign_destinations`, tạo investigation qua `/docs` bằng
request cùng scope/dataset UUID và thêm `"benign_destinations": ["192.168.56.20"]`.
Không sửa source code detector hay thêm nhãn vào fixture cho mục đích này.

Khuyến nghị chạy PN/N/J ít nhất ba lần ở các ca độc lập. Ghi pass/fail theo từng tiêu chí,
không chỉ báo cáo tổng số finding. Mẫu nhỏ này kiểm tra chức năng và khả năng quan sát,
chưa đủ ước lượng độ chính xác ngoài thực tế.

## 14. Mở rộng DNS tùy chọn

Phần chính dùng IP literal nên không có DNS là bình thường. Muốn có `dns.log`, dùng
resolver lab trên L. Chỉ làm nếu không có service DNS xung đột cổng 53:

```bash
sudo apt install dnsmasq-base
sudo ss -lunp | grep ':53 '
sudo dnsmasq --conf-file=/dev/null --no-daemon --no-hosts --no-resolv --bind-interfaces \
  --listen-address=192.168.56.20 --address=/lab.test/192.168.56.20 --log-queries
```

Nếu firewall cần luật, mở UDP/TCP 53 chỉ từ W trên adapter lab. Trong cửa sổ capture
riêng, trên Windows:

```powershell
Resolve-DnsName heartbeat.lab.test -Server 192.168.56.20 -DnsOnly
```

Không đổi DNS toàn máy. Địa chỉ trả về phải là `.20`. Xuất/đọc Zeek như ca trước và upload
source `zeek_dns`. Tên ngắn thông thường không nhất thiết tạo finding: detector DNS hiện
chủ yếu quan sát label dài, không mặc định coi mọi DNS request là C2.
[Tham số dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).

## 15. So sánh offline và LLM trên cùng log thật

Sau khi offline cho evidence đúng, có thể tạo investigation mới với **cùng dataset,
host, thời gian, strategy và budget**, chỉ đổi mode sang `gemini`/`deepseek`. Mode có
provider sẽ gửi dữ liệu liên quan tới dịch vụ ngoài; chỉ dùng log lab được phép gửi.
Không đưa `.env` hay API key vào dữ liệu upload.

Lưu cả hai kết quả; kiểm tra:

- Provider có thực sự hoàn thành hay chỉ fallback/timeout; xem assessment và warnings.
- Kết luận LLM có evidence ID đúng và phù hợp raw log không.
- Nó có phân biệt autorun configuration với autorun execution không.
- Nó có gọi heartbeat là malware chắc chắn hoặc bịa reputation/payload không.
- Thời gian, số lần gọi, tokens và phần giải thích có cải thiện so với offline không.

Một report có đoạn văn dài hơn chưa chứng minh chất lượng tốt hơn. `strategy=heuristic`
luôn chạy offline, nên không dùng strategy này để chứng minh đã kiểm thử provider.

## 16. Lưu báo cáo và sổ theo dõi ca

Trong ứng dụng, tải JSON và Markdown ở phần báo cáo; giữ cả request/scope và UUID.
Hoặc trên máy A dùng investigation UUID thật:

```powershell
$jobId = 'THAY-BANG-UUID-THAT'
$casePath = 'F:\TLCN_ATTT\Projects\multi-agent-security\verification\logs\captures\combined-01'
Invoke-WebRequest "http://127.0.0.1:8000/api/v1/investigations/$jobId/report" `
  -OutFile (Join-Path $casePath 'report-offline.json') -UseBasicParsing
Invoke-WebRequest "http://127.0.0.1:8000/api/v1/investigations/$jobId/report?format=markdown" `
  -OutFile (Join-Path $casePath 'report-offline.md') -UseBasicParsing
```

Mỗi ca ghi tối thiểu:

| Trường | Nội dung cần điền |
|---|---|
| Case ID, người chạy, ngày | Mã duy nhất và thời điểm UTC |
| Máy/OS/tool | Host chính xác, IP, Sysmon/Zeek version và image digest |
| Đồng hồ | Nguồn sync, offset/độ không chắc chắn |
| Ground truth | Script/tham số, request thành công/thất bại, Run Key dự kiến |
| Thu thập | Interface, capture filter, packet drop, thời gian, SHA-256 |
| Phân tích | Dataset UUID, investigation UUID, mode, strategy, scope/budget |
| Kết quả | Rule IDs, evidence IDs, correlation type, severity, coverage warnings |
| Sai khác | Thiếu event/flow, jitter, lời giải thích sai, giới hạn đã biết |
| Kết luận | Tiêu chí nào đạt/chưa đạt; không gộp chưa đo thành “pass” |

Lưu ghi chú vào `notes.md` trong thư mục ca. Bảo quản PCAP/EVTX gốc riêng với report;
report chỉ là kết quả suy luận, không thay được dữ liệu nguồn.

## 17. Chẩn đoán lỗi thường gặp

| Triệu chứng | Kiểm tra đầu tiên | Cách xử lý |
|---|---|---|
| Không kết nối HTTP | IP, route, server L1, cổng và firewall | Chỉ bắt đầu ca khi preflight 200 OK |
| Không có Sysmon Event 3 | Cấu hình đang nạp, channel, Event 255 | Bật NetworkConnect, xác nhận cập nhật thành công |
| Có Event 13 nhưng khác GUID với Event 3 | Có dùng reg.exe/curl.exe hay phiên khác không | Dùng script cùng process; không sửa GUID log |
| PCAP rỗng | Interface và filter; Linux có phải đích không | `ip route get`, xem packet trong lúc test |
| conn.log ít hơn request | Capture khởi động muộn/dừng sớm, drop, kết nối lỗi | Giữ capture toàn ca và xem manifest |
| Không có http.log | Thiếu payload, sai cổng, TLS thay plain HTTP | Dùng HTTP lab rõ ràng; xem PCAP và weird.log |
| HTTP có nhưng không có periodic | count, CV, nhóm IP/cổng/protocol | Đối chiếu mặc định ≥6/CV≤0,15, không chỉ nhìn GET |
| Không có tương quan mạnh | GUID, 5-tuple, clock≤2s, dataset scope | Đối chiếu raw từng nguồn; ghi giới hạn nếu không khớp |
| Chỉ có liên kết hypothesis | Không có Event 3 hoặc tuple lệch, mapping/time | Không tự nâng nó thành bằng chứng mạnh |
| Upload bị từ chối | Source, UTF-8, XML root, file >5 MB | Validate rồi chia file đúng định dạng |
| Zero evidence | Host FQDN, time UTC, UUID, filter IP | Lấy tên/thời gian từ log, bỏ filter lần lượt để chẩn đoán |
| Findings khác kỳ vọng | Noise, truncation, ca trước còn lẫn | Tách ca/dataset, đọc warnings và raw evidence |
| LLM lỗi dù offline tốt | API key, quota, model, timeout | Xem assessment; không coi offline fallback là provider pass |

Nếu Zeek báo checksum hoặc logs rỗng trên host capture, kiểm tra cờ `-C`; không dùng
cờ đó để che mất packet drop hay capture nhầm interface.

## 18. Dọn lab và phục hồi

Sau khi đã export bằng chứng, trên **đúng tài khoản Windows đã tạo value**:

```powershell
$labRunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -LiteralPath $labRunKey -Name SecurityLabMarker -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath $labRunKey -Name SecurityLabMarker -ErrorAction Stop
Get-ItemProperty -LiteralPath $labRunKey -Name SecurityLabMarker -ErrorAction SilentlyContinue
```

Chỉ xóa value `SecurityLabMarker`, không xóa toàn bộ Run key. Nếu muốn kiểm chứng logon
marker, làm trước khi xóa và thu riêng; Windows có thể trì hoãn/thay đổi hành vi startup,
đừng dùng thời điểm marker làm timestamp thay thế cho Event 13.

Ở Linux bấm Ctrl+C đúng terminal HTTP/DNS/capture của lab. Nếu đã thêm UFW rule thì xóa
đúng rule đó, ví dụ:

```bash
sudo ufw delete allow in on enp0s8 from 192.168.56.10 to 192.168.56.20 port 80 proto tcp
```

Khôi phục Sysmon config cũ nếu đã thay, không tự gỡ agent giám sát của tổ chức. Giữ log
và report tới khi kiểm chứng xong; không clear Windows Event Log và không chạy
`docker compose down -v` để “dọn thử” vì sẽ xóa volume database.

## 19. Tiêu chí hoàn thành một lượt PN

- [ ] Có `scenario.json`, không có request lỗi không được giải thích.
- [ ] Có PCAP, Sysmon EVTX/XML, Zeek conn/http và SHA-256 đối chiếu được.
- [ ] Ghi rõ Sysmon/Zeek version, interface, clock và packet drop.
- [ ] Validator đọc được file, host và khoảng thời gian đúng.
- [ ] Ứng dụng chỉ dùng dataset của ca, investigation hoàn thành, warnings đã được đọc.
- [ ] Finding/link được đối chiếu tới raw evidence; sai khác được ghi thành phát hiện.
- [ ] Báo cáo phân biệt cấu hình persistence, chu kỳ HTTP và mức độ chứng minh tương quan.
- [ ] Lưu report JSON/Markdown và dọn đúng Run value/các service lab.

Đạt checklist cho thấy quy trình thu–nhập–điều tra quan sát được hoạt động kiểm soát.
Để kết luận hiệu quả phát hiện tấn công thực tế, cần thêm tập ca đa dạng, nhãn độc lập
và đánh giá false positive/false negative ngoài các hành vi do chính script này tạo.
