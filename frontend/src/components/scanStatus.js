export function scannerStatusClass(status) {
  if (status === "completed") return "success";
  if (status === "failed") return "failed";
  return "pending";
}
