# ZKM

ZKM là cơ sở hạ tầng điện toán có thể kiểm chứng chung dựa trên [Plonky2](https://github.com/0xPolygonZero/plonky2) và [MIPS microarchitecture](https://en.wikipedia.org/wiki/MIPS_architecture), trao quyền cho Ethereum như lớp giải quyết toàn cầu.

# Xây dụng ứng dụng

Để xây dựng ứng dụng, zkm yêu cầu nightly toolchain mới nhất. Chỉ cần chạy `cargo build --release` trong thư mục zkm.

# Chạy các ví dụ

Một ví dụ toàn diện đã được trình bày trong [examples](./examples).

# Hướng dẫn dành cho cộng tác viên bên ngoài

Bất kỳ hình thức đóng góp bên ngoài nào đều được khuyến khích và hoan nghênh!

## Hướng dẫn chung cho pull request của bạn
DESC: PR = Pull request (Yêu cầu hợp nhất)

* PR sửa lỗi.
Trong phần mô tả PR, vui lòng mô tả rõ ràng nhưng ngắn gọn lỗi, bao gồm cách tái tạo và lỗi/ngoại lệ bạn gặp phải cũng như cách PR của bạn sửa lỗi.

* PR tích hợp tính năng mới
Trong phần mô tả PR, vui lòng mô tả rõ ràng nhưng ngắn gọn

> 1. Tính năng này làm gì?
> 2. Cách implement nó là gì?
> 3. Tất cả các PR cho các tính năng mới phải bao gồm một bộ thử nghiệm phù hợp.

* PR cải thiện hiệu suất

Để giúp lọc ra các kết sai lệch, mô tả PR để cải thiện hiệu suất phải xác định rõ ràng

> 1. Mục tiêu của phần cải thiện hiệu suất (Mỗi PR chỉ nên có 1 mục tiêu để tránh khó hiểu)
> 2. Cách đo hiệu suất?
> 3. Hiệu năng của thiết bị sử dụng (CPU, OS, #threads nếu có) trước và sau khi hợp nhất PR

# Giấy phép

ZKM được phân phối theo các điều khoản của giấy phép MIT.

# Bảo mật

Mã này chưa được kiểm tra và không được sử dụng trong bất kỳ hệ thống sản xuất nào.
