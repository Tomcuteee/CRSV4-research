# CRSV4-research
# Nghiên cứu và ứng dụng CRSV4 trong bảo mật hệ thống Web

## 1. Tóm tắt
CRSV4 là một hệ thống tường lửa ứng dụng web (Web Application Firewall – WAF) giả định, được thiết kế để bảo vệ máy chủ Apache khỏi các mối đe doạ lớp ứng dụng như SQL Injection, XSS, CSRF, brute force và thăm dò lỗ hổng. Bài báo mô tả kiến trúc, cơ chế chặn theo nhiều lớp, mô hình ngưỡng và tích hợp với Apache. Đồng thời đưa ra quy trình triển khai, cấu hình, quan trắc và phương pháp kiểm thử an toàn trong môi trường hai máy: một máy Ubuntu chạy Apache/CRSV4 và một máy sinh lưu lượng kiểm thử.

---

## 2. Giới thiệu
- Các hệ thống web hiện đại thường đối diện với tấn công lớp ứng dụng.
- CRSV4 cung cấp lớp phòng vệ theo thời gian thực, tích hợp chặt với Apache.
- Mục tiêu: mô tả nguyên lý, cơ chế chặn, cách tích hợp, kiểm thử với hai máy.

---

## 3. Nguyên lý hoạt động của CRSV4
- **Phân tích lưu lượng HTTP/HTTPS**: chuẩn hoá request, tách tham số.
- **Phát hiện bất thường**: signature-based, anomaly-based, rate-based.
- **Cơ chế tích điểm (scoring)**: mỗi vi phạm cộng điểm, tổng điểm so với ngưỡng.
- **Ngưỡng điển hình**: Warn ≥ 5, Challenge 6–7, Block ≥ 8.
- **Hành động phản ứng**: chặn request, yêu cầu CAPTCHA, ghi log chi tiết.

---

## 4. Cơ chế chặn và mô hình ngưỡng
| Loại vi phạm            | Điểm cộng | Hành động khi vượt ngưỡng |
|--------------------------|-----------|---------------------------|
| SQL Injection            | +4        | Block nếu tổng ≥ 8        |
| XSS                      | +3        | Block nếu tổng ≥ 8        |
| Tham số dài bất thường   | +2        | Challenge nếu tổng 6–7    |
| Rate-limit vượt ngưỡng   | +2        | Block nếu tổng ≥ 8        |
| CSRF thiếu token         | +3        | Block nếu tổng ≥ 8        |

---

## 5. Tích hợp CRSV4 với Apache
Ví dụ cấu hình trong `crsv4.conf`:

```apache
CRSV4Engine On
CRSV4AuditLog /var/log/crsv4/audit.log
CRSV4AnomalyThresholdWarn 5
CRSV4ChallengeThreshold 6
CRSV4AnomalyThresholdBlock 8
CRSV4RateLimitDefault "20/10s burst=40 action=block"
CRSV4CSRF On
CRSV4NormalizeURI On
