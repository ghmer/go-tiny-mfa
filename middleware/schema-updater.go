package middleware

import "log"

const (
	CurrentSchemaVersion uint8 = 1
)

func CheckSchemaUpgrade(version uint8) bool {
	return version < CurrentSchemaVersion
}

func UpgradeSchema(version uint8) (uint8, error) {
	log.Println("upgrading database schema version", version, "to current version", CurrentSchemaVersion)
	var err error
	switch version {
	case 0:
		{
			var upgradequery []string = make([]string, 3)
			upgradequery[0] = `ALTER TABLE serverconfig 
								ADD COLUMN schema_version smallint, 
								ADD COLUMN qrcode_bgcolor varchar(30), 
								ADD COLUMN qrcode_fgcolor varchar(30);`
			upgradequery[1] = `UPDATE serverconfig
								SET schema_version = 1, 
								qrcode_bgcolor = '0;0;0;0', 
								qrcode_fgcolor = '0;0;0;255' 
								WHERE ID = 1;`
			upgradequery[2] = `ALTER TABLE serverconfig
								ALTER COLUMN schema_version SET NOT NULL,
								ALTER COLUMN qrcode_bgcolor SET NOT NULL,
								ALTER COLUMN qrcode_fgcolor SET NOT NULL;`

			err = upgradeSchema(upgradequery)
			if err != nil {
				return 0, err
			}
		}
	}

	return CurrentSchemaVersion, nil
}

func upgradeSchema(upgradeQueries []string) error {
	connection, err := CreateConnection()
	if err != nil {
		return err
	}
	defer connection.Close()

	transaction, err := connection.Begin()
	if err != nil {
		return err
	}
	var transactionbroke bool = false
	for _, query := range upgradeQueries {
		_, err := transaction.Exec(query)
		if err != nil {
			transactionbroke = true
			break
		}
	}

	if transactionbroke {
		return transaction.Rollback()
	} else {
		return transaction.Commit()
	}
}
