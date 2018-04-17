package util

import (
	"errors"
	"fmt"
)

type Postgre struct {
	P P
}

func (this *Postgre) RunCmd(cmd string) (r string, e error) {
	username := ToString(this.P["username"], "postgres")
	database := ToString(this.P["name"], "postgres")
	host := ToString(this.P["host"], "citus1")
	port := 5432
	tpl := `psql -h %v -U %v -p %v %v -c "%v"`
	compose := fmt.Sprintf(tpl, host, username, port, database, cmd)
	r, e = Exec(compose)
	return
}


func (this *Postgre) LoadCsv(csv string, table string, split string) (r string, e error) {
	if IsEmpty(csv) || IsEmpty(table) {
		e = errors.New(fmt.Sprintf("Invalid csv %v, table %v, database", csv, table))
		return
	}
	return this.RunCmd(fmt.Sprintf(`\copy %v from '%v' CSV`,table, csv))
}
