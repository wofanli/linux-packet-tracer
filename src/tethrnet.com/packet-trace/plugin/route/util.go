package route

func rpFilterChk2Str(ret int) string {
	if ret == 0 {
		return "PASS"
	}
	return "DROP"
}
