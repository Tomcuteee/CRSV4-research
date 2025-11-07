# Bài báo khoa học: Kiến trúc, cơ chế chặn và triển khai CRSV4 bảo vệ hệ thống web trên Apache

## Tóm tắt
CRSV4 là một hệ thống phòng vệ ứng dụng web (Web Application Firewall – WAF) giả định, được thiết kế để bảo vệ máy chủ Apache khỏi các mối đe doạ lớp ứng dụng như SQL Injection, XSS, CSRF, brute force và thăm dò lỗ hổng. Công cụ này hoạt động theo cơ chế đa lớp, kết hợp phân tích chữ ký, phát hiện bất thường, kiểm soát hành vi và cơ chế tích điểm để đưa ra quyết định chặn hoặc cho phép request.  

Bài báo mô tả kiến trúc, cơ chế chặn theo nhiều lớp, mô hình ngưỡng và cách tích điểm, cùng quy trình triển khai, cấu hình, quan trắc và phương pháp kiểm thử an toàn trong môi trường hai máy: một máy Ubuntu chạy Apache/CRSV4 và một máy chuyên tạo lưu lượng kiểm thử. Nội dung tập trung vào phòng vệ, quản trị rủi ro và tối ưu, không bao gồm hướng dẫn tấn công chi tiết.

---

## Giới thiệu
Các hệ thống web hiện đại thường đối diện với tấn công lớp ứng dụng, nơi kẻ tấn công khai thác trực tiếp các điểm yếu trong logic xử lý dữ liệu.  
| Loại tấn công              | Mục tiêu chính                         | Hậu quả tiềm ẩn                  |
|-----------------------------|----------------------------------------|----------------------------------|
| SQL Injection (SQLi)        | Cơ sở dữ liệu                          | Rò rỉ hoặc thay đổi dữ liệu      |
| Cross-Site Scripting (XSS)  | Trình duyệt người dùng                 | Chiếm quyền điều khiển, đánh cắp cookie |
| CSRF                        | Phiên đăng nhập hợp lệ                 | Thực hiện hành động trái phép    |
| Command Injection / Path Traversal | Hệ điều hành, hệ thống file | Thực thi lệnh, truy cập file nhạy cảm |
| Brute force / Credential stuffing | Tài khoản người dùng           | Chiếm quyền truy cập, khóa tài khoản |

### Tác động
- **Rò rỉ dữ liệu nhạy cảm:** thông tin người dùng, mật khẩu, dữ liệu tài chính.  
- **Chiếm quyền điều khiển hệ thống:** thực thi lệnh trái phép, leo thang đặc quyền.  
- **Gián đoạn dịch vụ:** làm ứng dụng không thể hoạt động bình thường.  
- **Ảnh hưởng uy tín:** mất niềm tin của khách hàng và đối tác.

### Vai trò của CRSV4
CRSV4 được thiết kế để:
- Ngăn chặn các tấn công lớp ứng dụng ngay tại tầng web server (Apache).  
- Phân tích request theo nhiều lớp (pipeline) để phát hiện cả dấu hiệu rõ ràng lẫn bất thường tinh vi.  
- Cung cấp cơ chế **tích điểm (scoring)** và **ngưỡng (thresholds)** để ra quyết định linh hoạt: cảnh báo, thử thách, hoặc chặn.  
- Giúp quản trị viên vừa bảo vệ hệ thống, vừa giảm thiểu false positive, đảm bảo trải nghiệm người dùng hợp lệ.

**Mục tiêu của CRSV4:**
- Cung cấp lớp phòng vệ theo thời gian thực, tích hợp chặt với Apache.
- Giảm thiểu tấn công chủ động (SQLi, XSS, CSRF) và hành vi thăm dò (scanning, brute force).
- Cho phép quản trị viên giám sát, ghi log và tinh chỉnh ngưỡng để cân bằng giữa bảo mật và hiệu năng.

**Phạm vi nghiên cứu:**
- Kiến trúc và cách CRSV4 hoạt động theo nhiều lớp.
- Cơ chế chặn, mô hình ngưỡng (thresholds) và logic ra quyết định.
- Phương pháp tích hợp với Apache (module, reverse proxy, chuỗi filter).
- Quy trình thiết lập, giám sát và kiểm thử tuân thủ đạo đức.

---

## Kiến trúc hệ thống CRSV4

### Tổng quan kiến trúc
CRSV4 được thiết kế theo mô hình pipeline(Chuỗi bước liên tiếp) nhiều lớp:

- **Lớp tiền xử lý (Preprocessing):**
  - Chuẩn hoá request/response (URI normalization, decode/encode an toàn).
  - Tách tham số, xác định loại nội dung (MIME).
  - Phát hiện bất thường về định dạng.

- **Lớp phân tích ngữ cảnh HTTP:**
  - Kiểm tra headers, phương thức, đường dẫn, query, body.
  - Phát hiện phương thức nguy cơ cao theo ngữ cảnh (ví dụ PUT/DELETE bị hạn chế).

- **Lớp nhận diện mối đe doạ:**
  - **Signature-based:** So khớp với bộ quy tắc tấn công đã biết (regex, pattern, payload markers).
  - **Anomaly-based:** Chấm điểm bất thường theo đặc trưng (entropy input, độ dài bất thường, tỉ lệ ký tự đặc biệt, sai biệt hành vi theo người dùng/phiên/IP).
  - **Behavioral/Rate controls:** Giới hạn tốc độ, burst, nhịp truy cập, hành vi lặp.

- **Lớp ra quyết định (Decision Engine):**
  - Tổng hợp điểm (scores) từ các lớp.
  - So sánh với ngưỡng cấu hình.
  - Áp dụng hành động (chặn, thả, thêm thách thức, ghi log, gắn nhãn).

- **Lớp phản hồi và quan trắc:**
  - Ghi log chi tiết, xuất sự kiện.
  - Tích hợp SIEM.
  - Cơ chế “shadow mode” để thử nghiệm luật không gây gián đoạn.

### Dòng dữ liệu
1. Nhận request từ client → chuẩn hoá → trích xuất đặc trưng.
2. Áp dụng bộ quy tắc và mô hình anomaly để sinh các “vi phạm” (violations) và điểm.
3. Tổng hợp điểm theo weights/ngưỡng → xác định hành động.
4. Ghi log giàu ngữ cảnh, gắn ID sự kiện, hỗ trợ truy vết.
5. Phản hồi đến client và/hoặc upstream app.

### Ý nghĩa thực tiễn
- **Tính mô-đun:** Cho phép quản trị viên bật/tắt từng lớp tuỳ theo nhu cầu.
- **Khả năng mở rộng:** Có thể bổ sung thêm lớp mới (ví dụ: machine learning) mà không ảnh hưởng pipeline hiện tại.
- **Giảm false positive:** Shadow mode và anomaly scoring giúp tinh chỉnh ngưỡng trước khi áp dụng chặn thực tế.
- **Khả năng tích hợp:** Log và sự kiện có thể đưa vào SIEM/ELK để phân tích tập trung.

---

## Cơ chế chặn và mô hình ngưỡng của CRSV4
- CRSV4 áp dụng nhiều cơ chế chặn song song, từ chữ ký tấn công đã biết đến phân tích bất thường và kiểm soát hành vi. Các cơ chế này phối hợp để đảm bảo hệ thống web được bảo vệ toàn diện.
### Chặn theo chữ ký (Signature-based)
- **SQLi:** Nhận diện tổ hợp từ khoá và cấu trúc (UNION SELECT, stacked queries, comment evasion), phép toán logic bất thường trong tham số.
- **XSS:** Phát hiện thẻ script, event handler, URL `javascript:`, DOM sinks; chặn payload encode lẩn tránh (hex, URL, HTML entities).
- **Path traversal:** Nhận diện “../”, các biến thể mã hoá và backslash trong đường dẫn nhạy cảm.
- **Command injection:** Tổ hợp ký tự điều khiển shell, pipes, subshell, đường dẫn nhị phân nhạy cảm.

### Chặn theo bất thường (Anomaly-based) với điểm số
- **Đặc trưng điểm:**
  - Độ dài tham số vượt ngưỡng.
  - Tỉ lệ ký tự đặc biệt trên tổng độ dài.
  - Entropy chuỗi cao bất thường.(chuỗi có độ ngẫu nhiên cao, thường thấy trong payload mã hoá).
  - Sai biệt mô hình hành vi người dùng (tần suất, trình tự endpoint).
- **Ngưỡng gợi ý:**
  - Warning khi tổng điểm ≥ 5.
  - Challenge (CAPTCHA/token refresh) khi 6–7.
  - Block khi tổng điểm ≥ 8.
- **Weights:** Luật nhạy (ví dụ injection) có weight cao; anomaly nhẹ (độ dài) weight thấp. Quản trị có thể tinh chỉnh.

### Kiểm soát tốc độ và hành vi (Rate/Behavior)
- **Giới hạn theo IP/Token/Session:**
  - Ví dụ: tối đa 20 requests/10 giây/endpoint, burst 40; vượt ngưỡng → 429 Too Many Requests.
- **Tích điểm theo nhịp (burst scoring):**
  - Mỗi vi phạm nhịp tăng +1–2 điểm; gom theo sliding window.
- **Phong toả tạm thời (temporary ban):**
  - Nếu tái phạm nhiều lần trong khung 5–15 phút, tạm cấm 10–30 phút.

### Bảo vệ CSRF và tính toàn vẹn phiên
- **CSRF token:** Bắt buộc token không đoán được, ràng buộc phiên, kiểm tra header nguồn (Origin/Referer) theo whitelist.
- **SameSite cookies:** Thiết lập Strict/Lax cho cookies phiên; kết hợp HttpOnly, Secure.

### Chuẩn hoá và canonicalization (chuẩn hoá dữ liệu để tránh kẻ tấn công lợi dụng nhiều cách viết khác nhau của cùng một chuỗi).
- **Decode tuần tự:** URL decode, HTML entity decode, UTF-8 normalize, giới hạn số vòng decode để tránh “multiple-decoding attacks”.
- **Chuẩn hoá đường dẫn:** Loại bỏ “.”/“..”, backslash → slash, reject nếu trỏ ra ngoài root.

### Hành động phản ứng
- **Block:** 403/406 với trang lỗi chung; không phản hồi chi tiết payload.
- **Challenge:** Yêu cầu CAPTCHA, tăng độ khó hoặc token refresh.
- **Sanitization:** Trong một số trường hợp, loại bỏ đoạn nguy cơ, nhưng ưu tiên block với hành vi rõ ràng.
- **Log:** Ghi đầy đủ fingerprint, vi phạm, điểm, ngưỡng, hành động.

---

## Cơ chế tích điểm (Scoring) và logic ra quyết định

### Nguyên lý chung
- Mỗi luật bảo mật có trọng số (score).
- Khi request vi phạm một luật, CRSV4 cộng thêm số điểm tương ứng.
- Tổng điểm được so sánh với ngưỡng đã cấu hình để quyết định hành động.

| Loại vi phạm            | Điểm cộng | Hành động khi vượt ngưỡng |
|--------------------------|-----------|---------------------------|
| SQL Injection            | +4        | Block nếu tổng ≥ 8        |
| XSS                      | +3        | Block nếu tổng ≥ 8        |
| Tham số dài bất thường   | +2        | Challenge nếu tổng 6–7    |
| Rate-limit vượt ngưỡng   | +2        | Block nếu tổng ≥ 8        |
| CSRF thiếu token         | +3        | Block nếu tổng ≥ 8        |

### Ngưỡng ra quyết định
- **Cảnh báo:** Tổng điểm ≥ 5 → ghi log/cảnh báo.
- **Thử thách:** Tổng điểm 6–7 → yêu cầu CAPTCHA hoặc token mới.
- **Chặn:** Tổng điểm ≥ 8 → chặn request ngay.
Bạn muốn tôi chỉnh lại đoạn bạn viết thành một README.md rõ ràng, có format chuẩn Markdown, dễ đọc. Đây là phiên bản đã được biên tập lại:

---

### Ví dụ minh hoạ cơ chế tích điểm và chặn của CRSV4 :

- Để giúp mọi người dễ hình dung, dưới đây là hai request gửi đến endpoint thử nghiệm [`vulnerable.php`](./vulnerable.php) ở trên Apache.

## Giải thích ngắn gọn:
- CRSV4 sẽ phân tích và cộng điểm theo từng vi phạm, sau đó quyết định hành động dựa trên tổng điểm.
- **Loại tấn công:** Command Injection  
- **Khai thác:** Kẻ tấn công chèn thêm lệnh hệ thống (`ls; whoami`) vào tham số để ép ứng dụng thực thi trên server.  
- **CRSV4 xử lý:**  
  - Phát hiện dấu `;` dùng để nối lệnh → **+4 điểm**  
  - Nhận diện chuỗi lệnh hệ thống (`ls`, `whoami`) → **+3 điểm**  
  - Tham số bất thường về độ dài/entropy → **+1 điểm**  
- **Tổng điểm:** 8 → vượt ngưỡng **Block**

---

## Ví dụ 1: Request hợp lệ
```bash
curl -i -get --data-urlencode "cmd=echo EXOLOIT_OK" http://192.168.29.130/vulnerable.php
```
**Phân tích CRSV4:**
- Không có ký tự đặc biệt nguy hiểm.  
- Không có mẫu SQLi, XSS, hay command injection.  
- Không vượt ngưỡng độ dài tham số.

**Điểm cộng:** 0  

**Kết quả:**
```
HTTP/1.1 200 OK
EXOLOIT_OK
```

---

## 2. Request chứa chuỗi nghi ngờ
```bash
curl -i -get --data-urlencode "cmd=ls; whoami" http://192.168.29.130/vulnerable.php
```

**Phân tích CRSV4:**
- Phát hiện dấu `;` trong tham số → dấu hiệu **Command Injection** → **+4 điểm**.  
- Chuỗi chứa lệnh hệ thống (`ls`, `whoami`) → mẫu nguy hiểm bổ sung → **+3 điểm**.  
- Tham số dài hơn bình thường, entropy cao → **+1 điểm** (anomaly).  

**Tổng điểm:** 4 + 3 + 1 = **8**  

**So với ngưỡng:** Tổng điểm ≥ 8 → vượt ngưỡng **Block**  

**Kết quả:**
```
HTTP/1.1 493 Forbidden
```

---

## Bảng tổng hợp ví dụ

| Request                | Vi phạm phát hiện                                                                 | Điểm cộng | Tổng điểm | Hành động       |
|------------------------|-----------------------------------------------------------------------------------|-----------|-----------|-----------------|
| `cmd=echo EXOLOIT_OK`  | Không có                                                                          | 0         | 0         | 200 OK          |
| `cmd=ls; whoami`       | `;` (command injection) +4<br>`ls`/`whoami` (mẫu lệnh hệ thống) +3<br>Entropy cao +1 | 8      | 8         | 493 Forbidden   |

---

## Ý nghĩa minh hoạ
- Request hợp lệ → **200 OK** (cho phép).  
- Request nguy hiểm → **493 Forbidden** (bị chặn).  
- CRSV4 không chỉ dựa vào một dấu hiệu duy nhất, mà cộng dồn điểm từ nhiều lớp (signature, anomaly, behavior) để đưa ra quyết định cuối cùng.
---

#  Quy trình setup và thử nghiệm CRS v4

## 1️⃣ Chuẩn bị 2 máy

- **Máy chủ (Target):** Ubuntu VM – IP `192.168.29.130`  
  - Chạy Apache + ModSecurity + CRS v4  
  - Triển khai các file vulnerable để làm demo tấn công  

- **Máy tấn công (Attacker):** Kali Linux – IP `192.168.29.129`  
  - Gửi request tấn công bằng `curl` hoặc các công cụ pentest khác  
  - Không cần cài đặt phức tạp, Kali mặc định đã có `curl`  

---

## 2️⃣ Setup trên máy Ubuntu (Target)

### Bước 1: Cài Apache
```bash
sudo apt update
sudo apt install apache2 -y
```

### Bước 2: Cài ModSecurity
ModSecurity là WAF (Web Application Firewall) chạy như module của Apache, dùng để phân tích request.
```bash
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
sudo systemctl restart apache2
```

### Bước 3: Cài OWASP CRS v4
CRS (Core Rule Set) là tập hợp rule phát hiện tấn công ứng dụng web.
```bash
sudo git clone https://github.com/coreruleset/coreruleset.git /usr/share/modsecurity-crs
sudo cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf
```

### Bước 4: Include CRS vào cấu hình Apache
Trong file cấu hình ModSecurity (thường là file include trong `/etc/apache2/mods-enabled/security2.conf`).
Sử dụng lệnh sau để sửa file `security2.conf`:
```bash
nano  /etc/apache2/mods-enabled/security2.conf 
```
Sau khi mở ra tiến hành kích hoạt CRSv4 bằng cách thêm dòng dưới đây vào:
```
#Bat CRSv4
   IncludeOptional /usr/share/modsecurity-crs/crs-setup.conf
   IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
```


**Tại sao phải include?**
- `crs-setup.conf` chứa cấu hình chung (ngưỡng điểm, paranoia level, tuning).  
- `rules/*.conf` chứa toàn bộ rule phát hiện tấn công (SQLi, XSS, LFI, RCE...).  
- Nếu không include, Apache + ModSecurity sẽ chạy nhưng **không có rule nào để phát hiện/chặn**.  

Reload Apache để áp dụng:
```bash
sudo systemctl reload apache2
```

### Bước 5: Thêm các file vulnerable để demo
Trong `/var/www/html/` tạo các file:
- `vulnerable_page.php` → SQLi demo  
- `vulnerable.php` → Command Injection demo  
- `search.php` → XSS demo  
- `upload.php` → Upload demo  

---

## 3️⃣ Kiểm tra CRS v4 hoạt động

- Mở file `/etc/modsecurity/modsecurity.conf` và đảm bảo:
  ```
  SecRuleEngine On
  ```
- Sau đó có thể kiểm tra kỹ xem đã mở chưa bằng lệnh:
  ```
  grep -E "^SecRuleEngine" /etc/modsecurity/modsecurity.conf
  ```
  *Nếu hiện `SecRuleEngine On` thì ok

- Gửi một request hợp lệ từ Kali:
  ```bash
  curl -i -get --data-urlencode "cmd=echo OK" http://192.168.29.130/vulnerable.php
  ```
  → Kết quả: `200 OK`
  
   ```markdown
   ![Mô tả ảnh](images/ten-anh.png)
   ```



- Gửi một request tấn công từ Kali:
  ```bash
  
  curl -i -get --data-urlencode "cmd=ls; whoami" http://192.168.29.130/vulnerable.php
  ```
  → Nếu CRS hoạt động: `403 Forbidden` hoặc `493 Forbidden`

   ```markdown
   ![Mô tả ảnh](images/ten-anh.png)
   ```

---

## 4️⃣ Xem log để xác nhận CRS chặn

ModSecurity ghi log tại:
- `/var/log/apache2/error.log` (log lỗi chung)  
- `/var/log/apache2/modsec_audit.log` (audit log chi tiết)  

Xem log realtime:
```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```
Trong log sẽ có (Request gốc , Rule nào match ,  Điểm anomaly cộng thêm  , Hành động (block/challenge/log) )
   ```markdown
   ![Mô tả ảnh](images/ten-anh.png)
   ```
---
