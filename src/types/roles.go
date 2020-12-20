package types

//GetRoles - returns roles based on the permission level given
func GetRoles(role int) []string {
	switch role {
	case 999:
		return []string{"ADMIN", "DEFAULT"}
	default:
		return []string{"DEFAULT"}
	}
}
