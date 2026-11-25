from uuid import uuid4


VERIFY_ACTIONS = {
    "run_key": "Đối chiếu giá trị Run với cấu hình chuẩn và phiếu cài đặt. Kiểm tra chữ ký của tệp đích.",
    "startup": "Đối chiếu tệp trong Startup với gói cài đặt đã duyệt. Với lối tắt, kiểm tra tệp đích và chữ ký.",
    "scheduled_task": "Đối chiếu tên tác vụ, lịch chạy, tài khoản và chương trình đích với lịch quản trị.",
    "service": "Đối chiếu ImagePath, tài khoản dịch vụ và chữ ký của chương trình với bản cấu hình đã duyệt.",
    "registry_change": "Kiểm tra loại thay đổi registry, tiến trình thực hiện và phiếu bảo trì tương ứng.",
    "periodic_connection": "So sánh đích, cổng và khoảng cách giữa các kết nối với lịch cập nhật hoặc giám sát. Đối chiếu tiến trình từ Sysmon Event 3.",
    "long_dns_label": "Đối chiếu tên miền và kiểu truy vấn trong dns.log với dịch vụ hợp lệ. Kiểm tra tần suất lặp và máy nguồn.",
}


def recommend(findings):
    for finding in findings:
        persistence = finding["agent"] == "persistence"
        actions = [
            ("verify", VERIFY_ACTIONS.get(finding["rule_id"], "Đối chiếu thay đổi với chủ sở hữu tài sản và cấu hình chuẩn."),
             "Thực hiện trước khi thay đổi cấu hình máy hoặc mạng.", "Chỉ đọc và đối chiếu, chưa thay đổi hệ thống.",
             "Ghi lại chủ sở hữu, kết quả đối chiếu và bằng chứng hỗ trợ."),
            ("preserve", "Lưu log gốc và cấu hình liên quan, kèm mã băm SHA-256.",
             "Thực hiện trước khi khắc phục.", "Bản lưu bằng chứng có thể chứa dữ liệu nhạy cảm.",
             "Kiểm tra mã băm, thời gian và nguồn gốc bản ghi."),
            ("contain", "Cân nhắc cô lập máy và hạn chế các đích mạng đã xác minh là đáng ngờ.",
             "Chỉ áp dụng sau khi chuyên viên xác nhận hành vi độc hại đang diễn ra và được phép vận hành.",
             "Cô lập có thể gián đoạn dịch vụ; cần giữ kênh quản trị.",
             "Kiểm tra các hạn chế đã được duyệt và khả năng truy cập quản trị."),
            ("remediate", "Sao lưu rồi gỡ cấu hình tự chạy, tác vụ hoặc dịch vụ đã được xác nhận là trái phép." if persistence else
             "Xử lý tiến trình và cấu hình duy trì liên quan đã xác nhận là trái phép, sau khi thu bằng chứng.",
             "Chỉ thay đổi đối tượng đã xác minh là trái phép và sau khi được phép vận hành.",
             "Thay đổi có thể gián đoạn ứng dụng hợp lệ.",
             "Đối chiếu lại cấu hình và quét kiểm tra máy bị ảnh hưởng."),
            ("recover", "Khôi phục cấu hình đã được duyệt và theo dõi dấu hiệu tái xuất hiện.",
             "Thực hiện sau khi xem xét kết quả cô lập và khắc phục.", "Phối hợp với chủ sở hữu hệ thống khi phục hồi.",
             "Thu log Sysmon/Zeek mới và xác minh chuỗi hành vi cần xử lý đã dừng."),
        ]
        if finding["severity"] not in {"high", "critical"}:
            actions = actions[:2] + [("monitor", "Theo dõi hoạt động đã xác minh và đánh giá lại khi có bằng chứng mới.",
                                      "Áp dụng trong khi chờ xác minh mục đích của hoạt động.",
                                      "Chọn khoảng theo dõi phù hợp với hệ thống.",
                                      "Đối chiếu log mới với cấu hình và hoạt động chuẩn đã ghi nhận.")]
        finding["recommendations"] = [
            {"id": str(uuid4()), "phase": phase, "action": action, "condition": condition,
             "operational_impact": impact, "verification": verification, "status": "pending",
             "priority": index + 1, "evidence_ids": finding["evidence_ids"],
             "source": "Local analyst playbook v1.1", "technique_ids": finding["technique_ids"]}
            for index, (phase, action, condition, impact, verification) in enumerate(actions)
        ]


def consolidated_playbook(findings):
    """One ordered plan for the whole investigation; merge duplicate actions and references."""
    labels = {"verify": "Xác minh dấu hiệu", "preserve": "Bảo toàn bằng chứng", "contain": "Cô lập có điều kiện",
              "remediate": "Khắc phục sau xác minh", "recover": "Phục hồi và kiểm tra lại", "monitor": "Tiếp tục theo dõi"}
    groups = {}
    for finding in findings:
        for action in finding.get("recommendations", []):
            groups.setdefault(action["phase"], []).append(action)
    steps = []
    for phase, title in labels.items():
        actions = groups.get(phase, [])
        if not actions:
            continue
        unique = lambda field: " ".join(dict.fromkeys(a.get(field, "") for a in actions if a.get(field)))
        steps.append({"title": title, "action": unique("action"),
                      "condition": unique("condition") + " " + unique("operational_impact"),
                      "verification": unique("verification"),
                      "evidence_ids": list(dict.fromkeys(ref for a in actions for ref in a["evidence_ids"]))[:30]})
    return {"summary": ("Ưu tiên xác minh và lưu bằng chứng trước. Các bước thay đổi máy hoặc mạng chỉ thực hiện khi đã xác nhận và được phép."
                        if findings else "Chưa có dấu vết đủ điều kiện để đề xuất khắc phục cụ thể. Kiểm tra phạm vi dữ liệu và tiếp tục thu log."),
            "steps": steps, "limitations": ["Đề xuất không đồng nghĩa hành động đã được thực hiện; cần đối chiếu ngữ cảnh vận hành."]}
