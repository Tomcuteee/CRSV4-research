# Bài báo khoa học: Kiến trúc, cơ chế chặn và triển khai CRSV4 bảo vệ hệ thống web trên Apache

## Tóm tắt
CRSV4 là một hệ thống phòng vệ ứng dụng web (Web Application Firewall – WAF) giả định, được thiết kế để bảo vệ máy chủ Apache khỏi các mối đe doạ lớp ứng dụng như SQL Injection, XSS, CSRF, brute force và thăm dò lỗ hổng. Bài báo mô tả kiến trúc, cơ chế chặn theo nhiều lớp, mô hình ngưỡng và cách tích điểm, cùng quy trình triển khai, cấu hình, quan trắc và phương pháp kiểm thử an toàn, có đạo đức trong môi trường hai máy: một máy Ubuntu chạy Apache/CRSV4 và một máy chuyên tạo lưu lượng kiểm thử. Nội dung tập trung vào phòng vệ, quản trị rủi ro và tối ưu, không bao gồm hướng dẫn tấn công chi tiết.

---

## Giới thiệu
- **Bối cảnh tấn công lớp ứng dụng:** Hệ thống web hiện đại thường đối diện các kỹ thuật tấn công tinh vi ở lớp ứng dụng (SQLi, XSS, CSRF, brute-force).
- **Mục tiêu của CRSV4:** Cung cấp lớp phòng vệ theo thời gian thực, tích hợp chặt với Apache, giảm thiểu tấn công chủ động và hành vi thăm dò.
- **Phạm vi nghiên cứu:**
  - **Kiến trúc đa lớp và hoạt động của CRSV4.**
  - **Cơ chế chặn, mô hình ngưỡng (thresholds) và logic ra quyết định.**
  - **Quy trình thiết lập, giám sát và kiểm thử tuân thủ đạo đức.**

---

## Kiến trúc hệ thống CRSV4

### Tổng quan kiến trúc
- **Lớp tiền xử lý (Preprocessing):** Chuẩn hoá request/response (URI normalization, decode/encode an toàn), tách tham số, xác định loại nội dung (MIME), phát hiện bất thường về định dạng.
- **Lớp phân tích ngữ cảnh HTTP:** Kiểm tra headers, phương thức, đường dẫn, query, body; phát hiện phương thức nguy cơ cao theo ngữ cảnh (ví dụ hạn chế PUT/DELETE khi không cần thiết).
- **Lớp nhận diện mối đe doạ:**
  - **Signature-based:** So khớp với bộ quy tắc tấn công đã biết (regex, pattern, payload markers).
  - **Anomaly-based:** Chấm điểm bất thường theo đặc trưng (entropy input, độ dài bất thường, tỉ lệ ký tự đặc biệt, sai biệt hành vi theo người dùng/phiên/IP).
  - **Behavioral/Rate controls:** Giới hạn tốc độ, burst, nhịp truy cập, hành vi lặp.
- **Lớp ra quyết định (Decision engine):** Tổng hợp điểm (scores) từ các lớp, so với ngưỡng cấu hình; áp dụng hành động (chặn, thả, thêm thách thức, ghi log, gắn nhãn).
- **Lớp phản hồi và quan trắc:** Ghi log chi tiết, xuất sự kiện, tích hợp SIEM, và cơ chế “shadow mode” để thử nghiệm luật không gây gián đoạn.

### Dòng dữ liệu
- **Tiếp nhận và chuẩn hoá:** Nhận request từ client → chuẩn hoá URI/headers/body → trích xuất đặc trưng.
- **Áp dụng quy tắc và anomaly:** Thực thi bộ quy tắc signature và mô hình anomaly để sinh các “vi phạm” (violations) kèm điểm.
- **Tổng hợp và quyết định:** Tổng hợp điểm theo weights/ngưỡng → xác định hành động (block/challenge/allow).
- **Ghi nhận và truy vết:** Ghi log giàu ngữ cảnh, gắn ID sự kiện, hỗ trợ truy vết và phân tích.
- **Phản hồi:** Trả phản hồi phù hợp đến client và/hoặc upstream app (giữ kín chi tiết kỹ thuật nhằm tránh lộ thông tin).

---

## Cơ chế chặn và mô hình ngưỡng của CRSV4

### Chặn theo chữ ký (Signature-based)
- **SQL Injection:** Nhận diện tổ hợp từ khoá và cấu trúc (UNION SELECT, stacked queries, comment evasion), phép toán logic bất thường trong tham số; điểm ưu tiên cao do rủi ro trực tiếp.
- **XSS:** Phát hiện thẻ script, event handler, URL javascript:, DOM sinks; chặn payload encode lẩn tránh (hex, URL, HTML entities); kiểm soát output encoding ở phản hồi.
- **Path traversal:** Nhận diện “../”, các biến thể mã hoá và backslash trong đường dẫn nhạy cảm; chuẩn hoá đường dẫn để ngăn truy cập ngoài root.
- **Command injection:** Tổ hợp ký tự điều khiển shell, pipes, subshell, đường dẫn nhị phân nhạy cảm; hạn chế thực thi lệnh thông qua tham số.

### Chặn theo bất thường (Anomaly-based) với điểm số
- **Đặc trưng điểm:**
  - **Độ dài tham số vượt ngưỡng:** Input quá dài so với chuẩn; tăng điểm rủi ro mức vừa.
  - **Tỉ lệ ký tự đặc biệt:** Tỉ lệ cao bất thường (ví dụ dấu nháy, toán tử); tăng điểm rủi ro mức vừa.
  - **Entropy chuỗi cao:** Dấu hiệu obfuscation/encoding; tăng điểm rủi ro mức vừa.
  - **Sai biệt hành vi người dùng:** Tần suất, trình tự endpoint khác lệch mô hình bình thường; tăng điểm rủi ro theo thời gian.
- **Ngưỡng gợi ý:**
  - **Warning:** Khi tổng điểm ≥ 5 → ghi log/cảnh báo.
  - **Challenge:** Khi tổng điểm 6–7 → yêu cầu CAPTCHA/token refresh.
  - **Block:** Khi tổng điểm ≥ 8 → chặn request.
- **Weights:** Luật nhạy (ví dụ injection) có weight cao; anomaly nhẹ (độ dài) weight thấp; quản trị tinh chỉnh theo ngữ cảnh ứng dụng.

### Kiểm soát tốc độ và hành vi (Rate/Behavior controls)
- **Giới hạn theo IP/Token/Session:** Ví dụ tối đa 20 requests/10 giây/endpoint, burst 40; vượt ngưỡng → trả 429 Too Many Requests hoặc challenge.
- **Tích điểm theo nhịp (burst scoring):** Mỗi vi phạm nhịp tăng +1–2 điểm; gom theo sliding window để phát hiện flood/burst.
- **Phong toả tạm thời (temporary ban):** Nếu tái phạm nhiều lần trong khung 5–15 phút → tạm cấm 10–30 phút; ghi nhận fingerprint để theo dõi.

### Bảo vệ CSRF và tính toàn vẹn phiên
- **CSRF token:** Bắt buộc token khó đoán, ràng buộc phiên/người dùng; kiểm tra tiêu đề nguồn (Origin/Referer) theo whitelist, fallback an toàn khi thiếu.
- **Cookie chính sách:** Thiết lập SameSite (Strict/Lax) cho cookies phiên; kết hợp HttpOnly và Secure để hạn chế truy cập script và chỉ gửi qua HTTPS.
- **Kiểm tra ngữ cảnh:** Ràng buộc hành động nhạy (POST/PUT/DELETE) với xác thực và token hợp lệ; điểm cao nếu thiếu/vi phạm.

### Chuẩn hoá và canonicalization
- **Decode tuần tự:** URL decode, HTML entity decode, UTF-8 normalize; giới hạn số vòng decode để tránh “multiple-decoding attacks”.
- **Chuẩn hoá đường dẫn:** Loại bỏ “.”/“..”, chuyển backslash → slash, reject nếu trỏ ra ngoài root; ngăn bypass thông qua biến thể mã hoá.
- **Hạn chế parsing sâu:** Đặt giới hạn kích thước body/field, loại nội dung nguy cơ cao, và ngăn double-encoding phức tạp.

### Hành động phản ứng
- **Block:** Trả 403/406 với trang lỗi chung; không phản hồi chi tiết payload; ghi audit đầy đủ.
- **Challenge:** Yêu cầu CAPTCHA hoặc token refresh; giảm ma sát cho người dùng hợp lệ nhưng tăng chi phí cho kẻ tấn công.
- **Sanitization có kiểm soát:** Loại bỏ đoạn nguy cơ trong trường hợp an toàn; ưu tiên block khi hành vi rõ ràng.
- **Log và quan trắc:** Ghi fingerprint, vi phạm, điểm, ngưỡng, hành động; phát sự kiện đến SIEM/monitor để cảnh báo theo thời gian thực.

---

## Cơ chế tích điểm (Scoring) và logic ra quyết định

### Nguyên lý chung
- **Điểm theo luật:** Mỗi luật (signature/anomaly/rate/csrf) có trọng số (score).
- **Tổng điểm theo request:** Khi vi phạm một hoặc nhiều luật, điểm được cộng dồn cho request.
- **So sánh ngưỡng:** Tổng điểm so với ngưỡng Warn/Challenge/Block để quyết định hành động.

### Ví dụ điểm tham chiếu
- **SQL Injection mạnh:** +4 điểm (signature).
- **XSS cơ bản:** +3 điểm (signature).
- **Tham số dài bất thường:** +2 điểm (anomaly).
- **Vượt tần suất:** +2 điểm (rate).
- **Thiếu CSRF token:** +3 điểm (session integrity).

### Ngưỡng ra quyết định
- **Cảnh báo:** Tổng điểm ≥ 5 → ghi log/cảnh báo.
- **Thử thách:** Tổng điểm 6–7 → challenge (CAPTCHA/token refresh).
- **Chặn:** Tổng điểm ≥ 8 → block ngay; log chi tiết và gắn ID sự kiện.

---
