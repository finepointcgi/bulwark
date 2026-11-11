package main
import ("crypto/tls"; "database/sql"; "fmt"; "os/exec")
func h(db *sql.DB, name string) {
	exec.Command("sh", "-c", "ls "+name).Run()
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE n = '%s'", name))
	db.Query("SELECT * FROM t WHERE n = $1", name)
	_ = &tls.Config{InsecureSkipVerify: true}
}
