# ChaCha20–Poly1305 AEAD RTL

Lõi phần cứng AEAD ChaCha20–Poly1305 viết bằng Verilog, hướng tới tích hợp
vào hệ thống vi điều khiển RISC-V. Repository này chỉ chứa **RTL của lõi,
testbench cơ bản và project Quartus**. Không có CPU, bus, SoC, GUI hoặc UVM.

## Cấu trúc repository

```text
rtl/
  aead_chacha20_poly1305.v   Top của lõi AEAD
  chacha20_core.v            Lõi ChaCha20
  poly1305_core.v            Lõi Poly1305
testbench/
  tb_aead_core_gui.v         Testbench AEAD trực tiếp, in ciphertext và MAC
  aead_test_vector.txt       Vector đầu vào mẫu cho testbench AEAD
  run_aead_smoke.do          Script biên dịch và chạy mẫu trên ModelSim/Questa
  tb_chacha20_core_kat.v     Known-answer test cho ChaCha20
  tb_poly1305_arithmetic.v  Kiểm tra phép toán Poly1305 với mô hình số nguyên
quartus/
  aead_core/                Project tổng hợp top AEAD thuần
  aead_fit_harness/         Project fit/timing với giao tiếp nạp/đọc 32-bit
```

## Chạy mô phỏng AEAD

Cần ModelSim hoặc QuestaSim. Trong terminal, chuyển vào thư mục `testbench` và
chạy:

```powershell
cd testbench
vsim -c -do "do run_aead_smoke.do"
```

Nếu `vsim` chưa nằm trong `PATH`, dùng đường dẫn đầy đủ tới `vsim.exe` đã
cài trên máy. Script biên dịch ba file RTL, chạy `tb_aead_core_gui` với
`aead_test_vector.txt`, rồi in các dòng `Ciphertext:`, `MAC:` và số chu kỳ.
Vector mẫu chứa thông điệp **150 byte** và AAD **35 byte**. Với RTL hiện tại,
MAC mẫu là `325aa3bec68dd442d9ad28939a3f19df`.

Testbench AEAD này **in kết quả**; nó chưa tự so ciphertext/MAC với oracle.
Hai testbench còn lại kiểm tra riêng ChaCha20 bằng vector RFC 8439 và phép
toán Poly1305. Khi dùng một vector mới, cần tự so ciphertext/MAC với phần
mềm tham chiếu trước khi kết luận đúng chức năng.

## Tổng hợp bằng Quartus

Mục tiêu FPGA: **Cyclone II EP2C35F672C6 (board DE2)**; project được tạo
bằng **Quartus II 13.0 SP1**.

1. Mở `quartus/aead_fit_harness/aead_fit_harness.qpf`.
2. Chọn **Processing → Start Compilation**.
3. Trong **Compilation Report → Fitter → Resource Section → Fitter Resource
   Utilization by Entity**, xem hàng `u_aead` để lấy diện tích **riêng lõi**.
4. Trong **TimeQuest Timing Analyzer → Slow Model Fmax Summary**, xem Fmax
   sau fit.

Project `quartus/aead_core/aead_core.qpf` có top là lõi AEAD thuần, phù hợp
để xem kết quả **Analysis & Synthesis**. Top này có quá nhiều cổng I/O để
fit trực tiếp lên EP2C35. Project `aead_fit_harness` đưa dữ liệu vào/ra
qua giao tiếp 32-bit để chạy Fitter và TimeQuest.

Kết quả đo trên bản RTL hiện tại, với clock constraint **10 ns**, tối ưu
`AREA` và fitter seed 2:

| Chỉ số sau Fitter | Giá trị |
| --- | ---: |
| Fmax slow model | **103,14 MHz** |
| Logic elements của riêng `u_aead` | **5.751 LE** |
| Logic elements của toàn project, gồm harness | **6.823 LE** |
| Embedded multiplier 9-bit elements | **8** |

Đây là kết quả timing **giữa các thanh ghi** khi lõi nằm trong harness.
SDC mới khai báo clock; chưa ràng buộc input/output delay hoặc gán chân DE2.
Do đó kết quả này chưa xác nhận timing I/O khi chạy trên board và không phải
kết quả PPA ASIC.

## Giao tiếp và giới hạn hiện tại

`aead_chacha20_poly1305` nhận key 256-bit, nonce 96-bit, AAD theo block
16 byte và dữ liệu theo block tối đa 64 byte. Các lệnh `start_keygen`,
`start_aad`, `start_encrypt`/`start_decrypt`, `start_finalize` là xung một
chu kỳ; các tín hiệu `*_done` báo hoàn thành. Luồng thông thường là sinh
khóa Poly1305 một lần, nạp AAD, xử lý các block dữ liệu, rồi nạp block độ
dài và finalize để lấy MAC.

Trong chế độ giải mã, lõi tính plaintext và MAC nhưng **chưa có cổng nhận
MAC đầu vào hoặc tín hiệu authentication pass/fail**. Khối điều khiển tích
hợp phải so MAC và chỉ chấp nhận plaintext sau khi xác thực thành công.
Repository này chưa có bus hay bộ xử lý; giao tiếp hệ thống sẽ được thiết kế
ở giai đoạn tích hợp SoC.
