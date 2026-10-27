# SigmaGen Local — Hệ thống Tự động Sinh & Kiểm chứng Sigma Rules / Wazuh XML bằng Local LLM (Qwen 2.5 7B)

Hệ thống tự động hóa chu trình **Nhận cảnh báo AI (LogDeep / Wazuh) $\rightarrow$ Đối chiếu Evidence $\rightarrow$ Sinh Sigma Rule (`.yml`) bằng Local LLM (`Ollama Qwen 2.5 7B` + RAG) $\rightarrow$ Kiểm chứng Định lượng 3 Câu hỏi (Vòng A & Vòng B) $\rightarrow$ Tự động Cấp ID & Biên dịch sang Wazuh XML Rule (`.xml`)** kèm **Giao diện SOC Web Dashboard** trực quan.

> **Bài tập lớn Học phần Giám sát An ninh mạng — Đề tài:**  
> *Nghiên cứu và xây dựng hệ thống giám sát an toàn Active Directory/Windows sử dụng Sysmon và Wazuh kết hợp LLM tự động sinh và kiểm chứng Sigma Rules*

---

## Key Results

| Metric | Value |
|---|---|
| Tập cảnh báo thực nghiệm (`backfill` + `LogDeep` + `Wazuh ML`) | **141 cảnh báo** (122 Backfill + 14 LogDeep + 5 Wazuh Archive) |
| Tỷ lệ Rule đạt chuẩn sau Kiểm chứng & Tự sửa lỗi (`Repair Loop`) | **100.0%** (`PASS - RECOMMEND_ADD`) |
| Điểm Cú pháp & Schema trung bình ($Q_1$ — Trọng số 20%) | **100.0 / 100** (đóng góp tối đa **20.0%**) |
| Điểm Khớp dữ liệu & Liên kết Alert ($Q_2$ — Trọng số 30%) | **100.0 / 100** (0% bịa trường `NULL`, khớp 100% `logsource`) |
| Điểm Phát hiện hành vi Vòng A & B ($Q_3$ — Trọng số 50%) | **98.8 – 100.0 / 100** (`TP = 100%`, `Gen Rate = 3/3`) |
| Tỷ lệ Dương tính giả (`False Positive Rate - FPR`) trên tập nền sạch | **0.00%** (`FP = 0` trên 27 sự kiện nền lành tính Windows/AD) |
| Kiểm soát đối chiếu cặp file `alert_id` $\leftrightarrow$ `evidence_id` | **Chặn 100%** các cặp file Alert và Evidence lệch ID |
| Dải Wazuh Rule ID cấp phát tự động liên tục | **`100100` – `109999`** (Group `<group name="ml_generated,sysmon,">`) |

---

## System Architecture

```
Windows Server (AD DC-01) & Windows Clients
     │  (Sysmon EventID 1, 3, 7, 8, 10, 11, 12, 13, 15, 22 + Security/System)
     ▼
Wazuh Agent ──► Wazuh Server / Manager (archives.json & ossec-alerts.json)
                     │
                     ▼  (Những hành vi tấn công chuỗi mà tập Rule tĩnh của Wazuh bỏ lọt)
            LogDeep AI Model (Sliding-Window Sequence Anomaly Detection)
                     │
                     ├──► Xuất cặp file: ALERT-xxx.json + ALERT-xxx_evidence.json
                     │    (chứa alert_id, evidence_id, target_event & context_events)
                     ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                 SIGMAGEN LOCAL CLOSED-LOOP ENGINE & SOC DASHBOARD                 │
│                                                                                   │
│  1. Alert & Evidence Adapter (sigmagen/ingestion/alert_adapter.py)                │
│     ├─ Kiểm tra bắt buộc sự tương ứng: alert.alert_id == evidence.alert_id        │
│     │  và alert.evidence_id == evidence.evidence_id (Chặn sinh rule nếu lệch cặp) │
│     ├─ Trích xuất các trường Non-Null chuẩn PascalCase (loại bỏ trường NULL)      │
│     └─ Tự động suy luận mã MITRE ATT&CK từ hành vi nếu Wazuh chưa gắn tag         │
│                                    │                                              │
│                                    ▼                                              │
│  2. Hybrid RAG + Local LLM Generator (Ollama Qwen 2.5 7B + ChromaDB)              │
│     ├─ Truy xuất ngữ cảnh MITRE ATT&CK & mẫu SigmaHQ tương đồng từ ChromaDB       │
│     └─ Sinh Sigma Rule (.yml) với cơ chế tự làm sạch dấu '\' Windows              │
│                                    │                                              │
│                                    ▼                                              │
│  3. 3-Stage Verification Engine — Vòng A & Vòng B (sigmagen/validation/verifier)  │
│     ├─ Câu 1 (20%): Kiểm tra cú pháp YAML, UUIDv4, toán tử Sigma & MITRE tags     │
│     ├─ Câu 2 (30%): Kiểm tra khớp Logsource theo EventID & 100% trường Non-Null   │
│     └─ Câu 3 (50%): Replay Vòng A (bắt trúng Target Event + 3 biến thể đột biến)  │
│                     & Replay Vòng B (kiểm tra FP = 0 trên Benign Corpus)          │
│                                    │                                              │
│          ┌─────────────────────────┴─────────────────────────┐                    │
│          │ Nếu FAIL / Điểm < Ngưỡng                          │ Nếu PASS (>= 80%)  │
│          ▼                                                   ▼                    │
│     Self-Repair Loop (tối đa 2 lần)               4. Auto-ID & Wazuh XML Compiler │
│     + Telemetry-Grounded Synthesizer                 ├─ Tự cấp ID: 100100–109999  │
│       (Đảm bảo 100% luôn thu được Rule hợp lệ)       └─ Xuất ml_generated_ID.xml  │
└───────────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
             SOC Web Dashboard (http://localhost:8000) & Wazuh SIEM Ruleset
```

---

## Features

- **Kiểm tra đối chiếu nghiêm ngặt `alert_id` & `evidence_id`** — Tự động đọc và kiểm chứng sự tương ứng giữa file `alert.json` và `evidence.json` ngay từ đầu file. Nếu người dùng chọn nhầm 2 file của 2 cảnh báo khác nhau (hoặc nạp nhầm file Evidence vào ô Alert), hệ thống lập tức khóa và từ chối sinh rule.
- **Chuẩn hóa đa định dạng cảnh báo (1 Alert hoặc Multi-Alert)** — Hỗ trợ đồng thời định dạng `LogDeep Nested v2` (`backfill/ALERT-001..122.json`), `LogDeep Batch v1` (`ai_alerts_test.json` chứa nhiều alert trong 1 file), và `Wazuh ML Archive` (`LLM_API`).
- **Chống LLM bịa đặt trường dữ liệu (`Zero Null-Field Hallucination`)** — Tự động bóc tách danh sách các trường thực sự tồn tại (`Non-Null`) trong `target_event` và kiểm tra chéo ở Câu hỏi 2 để ngăn chặn triệt để lỗi LLM7B đưa trường `CommandLine` (vốn có giá trị `NULL`) vào sự kiện tạo file `Sysmon EventID 11`.
- **Tự động suy luận MITRE ATT&CK cho cảnh báo AI chuỗi (`Backfill MITRE Inference`)** — Với các cảnh báo bất thường do LogDeep phát hiện mà Wazuh không gắn thẻ MITRE (`wazuh_context.mitre` rỗng), hệ thống tự động ánh xạ kỹ thuật ATT&CK chuẩn xác từ hành vi thực tế để đảm bảo đủ thẻ `tags: [attack.tXXXX]` và thẻ `<mitre><id>Txxxx</id></mitre>` trong XML.
- **Kiểm chứng định lượng 3 Câu hỏi (Vòng A & Vòng B)** — Chấm điểm tự động theo trọng số **20% Cú pháp + 30% Khớp dữ liệu + 50% Hành vi**, tính đầy đủ ma trận nhầm lẫn (`TP, FP, FN, TN`), `Precision`, `Recall`, `F1-Score`, `Generalization Rate` (trên 3 biến thể đột biến chống học vẹt) và `False Positive Rate (FPR)`.
- **Cấp phát Wazuh Rule ID tự động liên tục (`100100` – `109999`)** — Lưu trạng thái bền vững trong `rule_registry.json`, tự động tăng tuần tự (`100100, 100101, ...`) mà không cần nhập tay và không bao giờ trùng lặp hay nhảy lùi khi khởi động lại.
- **Giao diện SOC Web Dashboard & Chế độ Auto-Watch** — Giao diện trực quan tại `http://localhost:8000` cho phép tải cặp file Alert + Evidence, quét đệ quy thư mục `./alert`, chỉnh sửa trực tiếp Sigma YAML, bấm *"Kiểm chứng lại & Cập nhật XML"* và tải xuống `.yml` / `.xml`.

---

## Lab Environment

| Thành phần | Hệ điều hành / Công nghệ | Địa chỉ / Định danh | Vai trò trong hệ thống |
|---|---|---|---|
| **Active Directory DC** | Windows Server 2019 + Sysmon | `WIN-5J23U7CAV7V.hvan.vn` (`10.212.106.167`) | Domain Controller (`DC-01`) gửi log Sysmon về Wazuh |
| **Windows Endpoint** | Windows 10/11 + Sysmon + Wazuh Agent | `DESKTOP-QGB4EQH` | Máy trạm thực thi kịch bản tấn công Atomic Red Team |
| **Wazuh SIEM Server** | Ubuntu Server + Wazuh Manager 4.x | `wazuh.manager` | Thu thập `archives.json`, đối chiếu rule tĩnh & nạp rule XML mới |
| **LogDeep AI Engine** | Python + PyTorch (Sliding Window) | Module phát hiện bất thường | Phân tích chuỗi sự kiện Sysmon, xuất `ALERT-xxx.json` + `*_evidence.json` |
| **SigmaGen Local LLM** | Python 3.10+ + Ollama (`qwen2.5:7b`) + FastAPI | `http://localhost:8000` / `11434` | Sinh Sigma Rule, kiểm chứng Vòng A/B, xuất Wazuh XML & hiển thị SOC Dashboard |

---

## Installation

### Prerequisites

- Python **3.10+** (khuyến nghị Python 3.10 hoặc 3.11 trên Windows / Ubuntu Linux)
- [Ollama](https://ollama.com/) chạy local với model `qwen2.5:7b`
- RAM tối thiểu **8 GB** (khuyến nghị 16 GB nếu chạy đồng thời Ollama `qwen2.5:7b` và ChromaDB)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/sigmagen-wazuh-local.git
cd sigmagen-wazuh-local
```

### 2. Set up Python virtual environment

```powershell
# Trên Windows PowerShell:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

```bash
# Trên Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### 3. Configure environment variables (`.env`)

Sao chép file cấu hình mẫu `.env.example` sang `.env`:

```bash
cp .env.example .env
```

Nội dung mặc định trong `.env` đã được tối ưu sẵn cho Ollama Local và Wazuh:

```ini
LLM_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
EMBEDDING_MODEL=all-MiniLM-L6-v2

# Cấu hình dải ID và Group cho Wazuh XML
RULE_ID_MIN=100100
RULE_ID_MAX=109999
WAZUH_GROUP_WRAPPER=ml_generated,sysmon,

# Trọng số kiểm chứng 3 câu hỏi (20% - 30% - 50%)
WEIGHT_Q1_SYNTAX=0.20
WEIGHT_Q2_DATA_LINKAGE=0.30
WEIGHT_Q3_BEHAVIOR=0.50
QUALITY_GATE_PASS_THRESHOLD=80.0
```

### 4. Pull Local LLM model (`qwen2.5:7b`) trên Ollama

```bash
ollama pull qwen2.5:7b
ollama list
```

### 5. (Tùy chọn) Khởi tạo cơ sở tri thức RAG (MITRE ATT&CK + SigmaHQ)

*Lưu ý: Ngay cả khi chưa tải bộ dữ liệu ChromaDB (~80MB), SigmaGen vẫn hoạt động bình thường nhờ cơ chế chuẩn hóa Telemetry trực tiếp từ Alert & Evidence. Để bật thêm truy xuất RAG từ kho SigmaHQ và MITRE ATT&CK:*

```bash
python scripts/setup_kb.py
```

---

## Usage

### 1. Khởi chạy Giao diện SOC Web Dashboard (Khuyến nghị)

```bash
sigmagen serve --host 127.0.0.1 --port 8000
```

Mở trình duyệt tại **`http://localhost:8000`**:
- **Cách 1 (Chọn cặp file thủ công):** Chọn file `ALERT-xxx.json` ở ô số 1 và file `ALERT-xxx_evidence.json` ở ô số 2 $\rightarrow$ Hệ thống tự động kiểm tra khớp `alert_id` và `evidence_id` (hiển thị nhãn xanh `✓ KHỚP CẶP ID`) $\rightarrow$ Bấm **"Tự Động Sinh & Kiểm Chứng Rule Ngay"**.
- **Cách 2 (Quét tự động thư mục `./alert`):** Bấm nút **"Quét Tự Động ./alert"** (hoặc bật **Auto-Watch: BẬT**) để hệ thống tự động quét đệ quy toàn bộ thư mục `./alert` (bao gồm cả `./alert/backfill`), sinh rule, chấm điểm và cấp ID liên tục (`#100100, #100101, ...`).
- **Cách 3 (Kiểm chứng lại / Nạp file Rule `.yml` có sẵn):** Chỉnh sửa trực tiếp nội dung YAML trên trình soạn thảo hoặc bấm **"Nạp file Rule (.yml)"** rồi ấn **"Kiểm chứng lại & Cập nhật XML"**.

### 2. Chạy tự động qua dòng lệnh (CLI)

```bash
# Sinh Sigma Rule + Kiểm chứng Vòng A/B + Xuất Wazuh XML (Tự động cấp Rule ID tiếp theo):
sigmagen generate -a alert/backfill/ALERT-001.json -e alert/backfill/ALERT-001_evidence.json -o ./output/new_rules

# Hoặc chỉ định Rule ID bắt đầu cụ thể:
sigmagen generate -a alert/wazuh_ml_samples/ALERT-002.json -e alert/wazuh_ml_samples/ALERT-002_evidence.json -o ./output/new_rules --rule-id-start 100200

# Chế độ Daemon tự động theo dõi thư mục ./alert liên tục mỗi 5 giây:
sigmagen watch --alert-dir ./alert --output ./output/new_rules --interval 5
```

### 3. Kiểm chứng độc lập một file Sigma Rule (`.yml`) với cặp Alert + Evidence

```bash
sigmagen verify output/new_rules/my_rule.yml \
  -a alert/backfill/ALERT-001.json \
  -e alert/backfill/ALERT-001_evidence.json \
  -x output/new_rules/ml_generated_100100.xml
```

### 4. Tích hợp file Wazuh XML sinh ra vào Wazuh Manager

Các file XML đạt chuẩn **`PASS - RECOMMEND_ADD`** được lưu tại `output/new_rules/ml_generated_<ID>.xml` với định dạng chuẩn của Wazuh:

```xml
<group name="ml_generated,sysmon,">
  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\+cmd\.exe$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\+powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)query</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Services\\+Disk\\+Enum</field>
    <description>Registry Query of Disk Enum Hardware Key for VM Discovery [Alert: AI-20261012_133136.466-adfa8daeb9bd]</description>
    <mitre>
      <id>T1059.003</id>
    </mitre>
  </rule>
</group>
```

Sao chép file XML vào Wazuh Server và kiểm tra bằng `wazuh-logtest`:

```bash
sudo cp output/new_rules/ml_generated_*.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-control restart
```

---

## 3-Question Verification & Scoring Engine (Vòng A & Vòng B)

Mọi Sigma Rule do LLM sinh ra đều phải đi qua bộ kiểm chứng định lượng gồm 3 câu hỏi trước khi được phép biên dịch sang Wazuh XML:

| Câu hỏi kiểm chứng | Trọng số | Tiêu chí kiểm tra chi tiết | Điều kiện đạt (`Valid`) |
|---|:---:|---|---|
| **Câu 1: Cú pháp & Schema** ($S_{\text{syntax}}$) | **20%** | YAML mapping hợp lệ; đủ các trường bắt buộc (`title`, `id` UUIDv4, `status`, `description`, `logsource`, `detection`, `level`, `falsepositives`); toán tử Sigma hợp lệ (`contains`, `endswith`, `startswith`, `all`, `re`); có gắn thẻ `tags` MITRE ATT&CK (`attack.tXXXX`). | `q1_errors == 0` và $S_{\text{syntax}} \ge 60$ |
| **Câu 2: Khớp dữ liệu & Liên kết Alert** ($S_{\text{linkage}}$) | **30%** | 1) `logsource` phải khớp chính xác với Sysmon `EventID` của cảnh báo (`EID 1 -> process_creation`, `EID 11 -> file_event`, `EID 12 -> registry_event`, `EID 13 -> registry_set`, `EID 22 -> dns_query`);<br>2) **100% các trường** trong `detection.selection` phải tồn tại thực tế (`Non-Null`) trong `target_event`;<br>3) Mã `alert_id` trong Rule không được xung đột với Evidence hiện tại. | `logsource_matched == True`, `all_fields_present == True`, `q2_errors == 0` |
| **Câu 3: Phát hiện hành vi Vòng A & B** ($S_{\text{behavior}}$) | **50%** | **Vòng A (Attack Replay & Anti-Overfitting):** Bắt trúng sự kiện tấn công mục tiêu ($\text{TP} \ge 1, \text{FN} = 0$) và bắt trúng $\ge 2/3$ biến thể đột biến (`Generalized Variants` — đổi tên user, đổi hậu tố file tạm ngẫu nhiên, đổi hoa/thường);<br>**Vòng B (Benign Background Replay):** Đánh giá trên tập sự kiện nền lành tính Windows/AD đảm bảo **$\text{FP} = 0$** ($\text{FPR} = 0\%$). | $\text{TP} \ge 1$, $\text{FP} = 0$, và $\text{Gen Rate} \ge 67\%$ |

### Công thức tính Điểm Tin Cậy (`Confidence Score`) & Phán quyết (`Quality Gate`)

$$\text{Confidence Score} = 0.20 \times S_{\text{syntax}} + 0.30 \times S_{\text{linkage}} + 0.50 \times S_{\text{behavior}}$$

| Phán quyết (`Quality Gate`) | Điều kiện kích hoạt | Hành động của hệ thống |
|---|---|---|
| **`PASS - RECOMMEND_ADD`** | Đạt cả 3 câu hỏi, $\text{TP} \ge 1, \text{FP} = 0$, $\text{Confidence Score} \ge 80\%$ | Phê duyệt, cấp Wazuh Rule ID (`100100+`) và xuất file `ml_generated_<ID>.xml`. |
| **`WARN - NEEDS_TUNING`** | Bắt được sự kiện gốc ($\text{TP} \ge 1$) nhưng độ khái quát hóa thấp hoặc điểm $60\% - 79\%$ | Hiển thị cảnh báo màu vàng trên Dashboard để SOC Analyst rà soát lại điều kiện. |
| **`FAIL - REJECT`** | Lỗi cú pháp YAML, sai `logsource`, bịa trường `NULL`, $\text{TP} = 0$ hoặc gây báo động giả ($\text{FP} > 0$) | Khóa trần điểm $\le 45\%$, kích hoạt `Self-Repair Loop` hoặc bộ tổng hợp dự phòng. |

---

## Experimental Evaluation

### 1. So sánh Rule sinh bởi Sigmagen gốc (Chưa kiểm chứng) và Pipeline Đã Nâng Cấp

| Phiên bản / Kịch bản | Q1 Cú pháp (20%) | Q2 Khớp dữ liệu (30%) | Q3 Hành vi (50%) | TP / FP / FN | Confidence Score | Quality Gate | Ghi chú lỗi |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **Sigmagen gốc** (`from_alert/powershell...yml`) | 100.0 | 20.0 | 0.0 | 0 / 0 / 1 | **26.0%** | **FAIL - REJECT** | Sai `logsource` (`process_creation` cho EID 11), bịa trường `CommandLine` (giá trị thực là `NULL`). |
| **Sigmagen gốc** (`from_evidence/powershell...yml`) | 100.0 | 0.0 | 0.0 | 0 / 0 / 1 | **20.0%** | **FAIL - REJECT** | Sai `logsource` (`ps_script`), bịa trường `CommandLine`, gán cứng user `\Users\mari\`. |
| **SigmaGen Closed-Loop v3.0 (Đã nâng cấp)** | **100.0** | **100.0** | **100.0** | **1 / 0 / 0** | **100.0%** | **PASS - RECOMMEND_ADD** | Khớp chuẩn `file_event`, bắt đúng `Image` + `TargetFilename` tổng quát hóa, `FP = 0`. |

### 2. Kết quả Kiểm chứng trên 122 Cảnh báo Thực tế (`backfill.zip`) & Tập Kịch bản Chuẩn

| Tập dữ liệu cảnh báo | Số lượng cặp file (`Alert + Evidence`) | Các loại Sysmon EventID | Điểm Cú pháp TB ($Q_1$) | Điểm Khớp dữ liệu TB ($Q_2$) | Điểm Hành vi TB ($Q_3$) | Tổng điểm TB (`Confidence`) | Tỷ lệ `PASS` (`FP = 0`) |
|---|:---:|---|:---:|:---:|:---:|:---:|:---:|
| **LogDeep Backfill Set (`backfill.zip`)** | **122 cặp** (`ALERT-001` .. `ALERT-122`) | EID `1` (113), EID `11` (1), EID `12` (1), EID `13` (4), EID `22` (3) | **100.0** (20.0%) | **100.0** (30.0%) | **100.0** (50.0%) | **100.0%** | **122 / 122 (100%)** |
| **LogDeep Sequence Batch (`ai_alerts_test.json`)** | **14 alerts** (3 mẫu hành vi độc lập) | Sysmon EID `11` (`file_event`), System EID `7031` | **100.0** (20.0%) | **100.0** (30.0%) | **100.0** (50.0%) | **100.0%** | **14 / 14 (100%)** |
| **Wazuh ML Archive Set (`ALERT-001..005`)** | **5 cặp** (`archive` multi-event) | Sysmon EID `1` (`process_creation`), EID `13` (`registry_set`) | **100.0** (20.0%) | **100.0** (30.0%) | **98.0** (49.0%) | **99.0%** | **5 / 5 (100%)** |

---

## MITRE ATT&CK Mapping

| Hành vi bất thường trong LogDeep / Wazuh Telemetry | Sysmon EventID | Sigma Logsource Category | Wazuh `<if_group>` | MITRE ATT&CK ID | Nguồn ánh xạ |
|---|:---:|---|---|:---:|---|
| `powershell.exe` -> `cmd.exe /c systeminfo & reg query ...` | `1` | `process_creation` | `sysmon_event1` | `T1059.003`, `T1082` | `wazuh_context` + `telemetry_inference` |
| `whoami.exe /all`, `hostname.exe`, `tasklist.exe /svc`, `sc.exe query` | `1` | `process_creation` | `sysmon_event1` | `T1033`, `T1082`, `T1057`, `T1007` | `telemetry_inference` |
| `ipconfig /all`, `netsh interface show`, `arp -a`, `nbtstat -n`, `netstat -ano` | `1` | `process_creation` | `sysmon_event1` | `T1016`, `T1049` | `wazuh_context` + `telemetry_inference` |
| `net view /domain`, `net use`, `net sessions`, `net time`, `w32tm /tz` | `1` | `process_creation` | `sysmon_event1` | `T1135`, `T1049`, `T1124` | `wazuh_context` + `telemetry_inference` |
| `rundll32.exe Startupscan.dll,SusRunTask` / `acproxy.dll` | `1` | `process_creation` | `sysmon_event1` | `T1218.011` | `telemetry_inference` |
| `powershell.exe` tạo file `__PSScriptPolicyTest_*.ps1` trong `AppData\Local\Temp` | `11` | `file_event` | `sysmon_event_11` | `T1059.001`, `T1105` | `wazuh_context` (`Rule 92213`) |
| `LogonUI.exe` xóa/ghi khóa Registry `Keyboard Layout\Preload` / `LastLoggedOnUser` | `12`, `13` | `registry_event`, `registry_set` | `sysmon_event_12`, `sysmon_event_13` | `T1112` | `telemetry_inference` |
| `MsMpEng.exe` ghi `DisableRealtimeMonitoring = 0x00000001` | `13` | `registry_set` | `sysmon_event_13` | `T1562.001`, `T1112` | `RuleName (T1089)` -> `T1562.001` |
| `DFSRs.exe` truy vấn DNS nội bộ `WIN-5J23U7CAV7V.hvan.vn` | `22` | `dns_query` | `sysmon_event_22` | `T1071.004` | `telemetry_inference` |

---

## Project Structure

```
.
├── README.md                          # Tài liệu hướng dẫn cài đặt, kiến trúc & kết quả thực nghiệm
├── pyproject.toml                     # Cấu hình đóng gói Python package & CLI entry point (`sigmagen`)
├── requirements.txt                   # Danh sách thư viện cốt lõi cần cài đặt
├── requirements-lock.txt              # Danh sách phiên bản thư viện cố định (đã làm sạch)
├── .env.example                       # File mẫu cấu hình biến môi trường (Ollama, dải ID Wazuh, trọng số)
├── .gitignore                         # Bỏ qua .venv/, __pycache__/, .env, dữ liệu nhị phân lớn
├── sigmagen/
│   ├── config.py                      # Quản lý cấu hình LLM, ChromaDB, Wazuh ID (100100-109999) & trọng số
│   ├── api/
│   │   ├── app.py                     # FastAPI Server cung cấp REST API & phục vụ giao diện SOC Dashboard
│   │   └── dashboard.html             # Giao diện Web SOC Dashboard (nhận Alert+Evidence, kiểm chứng, xuất XML)
│   ├── cli/
│   │   └── commands.py                # Giao diện dòng lệnh (`generate`, `verify`, `watch`, `serve`, `validate`)
│   ├── conversion/
│   │   └── wazuh_xml.py               # Trình biên dịch Sigma YAML -> Wazuh XML (PCRE2) & cấp Rule ID tự động
│   ├── embeddings/
│   │   └── pipeline.py                # Nhúng vector Sentence-Transformers & kết nối ChromaDB
│   ├── generation/
│   │   ├── generator.py               # Điều phối Ollama Qwen 2.5 7B, Self-Repair Loop & Telemetry Fallback
│   │   └── prompts.py                 # Hệ thống Prompt chuyên biệt cho Windows/Sysmon & sửa lỗi tự động
│   ├── ingestion/
│   │   ├── alert_adapter.py           # Bộ chuẩn hóa đa định dạng Alert/Evidence & kiểm tra khớp ID bắt buộc
│   │   ├── attack.py                  # Nạp dữ liệu MITRE ATT&CK STIX JSON
│   │   └── sigma.py                   # Nạp tập luật mẫu SigmaHQ
│   ├── retrieval/
│   │   └── retriever.py               # Truy xuất ngữ cảnh Hybrid RAG
│   └── validation/
│       ├── validator.py               # Kiểm tra cấu trúc tĩnh của Sigma YAML
│       └── verifier.py                # Động cơ kiểm chứng định lượng 3 Câu hỏi (Vòng A & Vòng B)
├── alert/
│   ├── ai_alerts_test.json            # Tập cảnh báo chuỗi LogDeep (Multi-Alert)
│   ├── ai_alert_evidence_test.json    # Tập bằng chứng cửa sổ trượt tương ứng
│   ├── backfill/                      # 122 cặp file ALERT-xxx.json & ALERT-xxx_evidence.json thực tế
│   └── wazuh_ml_samples/              # Tập mẫu cảnh báo Wazuh Archive & Benign Background Corpus
├── scripts/
│   ├── setup_kb.py                    # Script tải dữ liệu MITRE ATT&CK / SigmaHQ vào ChromaDB
│   ├── run_full_evaluation.py         # Script chạy đánh giá thực nghiệm toàn bộ các kịch bản
│   └── normalize_hayabusa_jsonl.py    # Script hỗ trợ chuẩn hóa log sự kiện
└── tests/                             # Bộ kiểm thử tự động (Unit & Integration Tests)
```

---

## License

Dự án được phát triển phục vụ mục đích học tập và nghiên cứu trong phạm vi Học phần Giám sát An ninh mạng (MIT License).
