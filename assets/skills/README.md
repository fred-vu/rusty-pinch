# Skills (Starter Bundle)

Thư mục này chứa các **starter skill** được track trong git.

Khi `rusty-pinch` khởi động, runtime sẽ tự sync các file `*.rhai` từ:

- `assets/skills/`

sang:

- `${RUSTY_PINCH_WORKSPACE}/skills`

chỉ khi file đích **chưa tồn tại**.

## Skill hiện có

- `weather.rhai`: lấy thời tiết từ `wttr.in` (không cần API key).

## Cách dùng với Cargo (local)

Từ root repo:

```bash
# 1) Kiểm tra skill đã được sync vào workspace
cargo run -- skills list

# 2) Compile-check skill
cargo run -- skills dry-run --name weather

# 3) Chạy current weather
cargo run -- skills run --session weather --name weather --args "Hanoi"

# 4) Chạy forecast
cargo run -- skills run --session weather --name weather --args "forecast|Hanoi"

# 5) Chạy rain-focused output
cargo run -- skills run --session weather --name weather --args "rain|Hanoi"

# 6) Chạy detailed output
cargo run -- skills run --session weather --name weather --args "detail|Hanoi"
```

## Cách dùng trên Raspberry Pi (docker-compose)

Từ `deploy/container`:

```bash
# 1) Đảm bảo container telegram đang chạy
docker-compose -f docker-compose.rpi.yml up -d rusty-pinch-telegram

# 2) Kiểm tra skill trong container
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch skills list

# 3) Compile-check
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch skills dry-run --name weather

# 4) Chạy current weather
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch skills run --session weather --name weather --args "Hanoi"

# 5) Chạy forecast
docker-compose -f docker-compose.rpi.yml exec rusty-pinch-telegram rusty-pinch skills run --session weather --name weather --args "forecast|Hanoi"
```

## Args contract của weather.rhai

- `"<location>"` -> current weather
- `"forecast|<location>"` -> forecast
- `"rain|<location>"` -> precipitation-focused
- `"detail|<location>"` -> detailed current
- args rỗng -> dùng mặc định `London`

## Lưu ý vận hành

- Skill dùng `https://wttr.in`, nên cần outbound network.
- Nếu timeout (`curl code 28`), kiểm tra DNS/network từ host/container.
- Vì sync là **copy-if-missing**, nếu bạn đã có file `workspace/skills/weather.rhai` cũ thì bản mới trong `assets/skills/` sẽ không ghi đè.
  - Muốn cập nhật từ `assets`, hãy xóa file cũ trong `${RUSTY_PINCH_WORKSPACE}/skills/` rồi restart app/container.
