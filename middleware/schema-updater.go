package middleware

import (
	"errors"
	"log"
)

const (
	CurrentSchemaVersion uint8 = 2
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
			var upgradequery []string = make([]string, 5)
			upgradequery[0] = `ALTER TABLE serverconfig 
                                ADD COLUMN schema_version smallint;`
			upgradequery[1] = `UPDATE serverconfig
                                SET schema_version = 1 
                                WHERE ID = 1;`
			upgradequery[2] = `ALTER TABLE serverconfig
                                ALTER COLUMN schema_version SET NOT NULL;`
			upgradequery[3] = `CREATE TABLE IF NOT EXISTS qr_code_config (
                                id serial NOT NULL,
                                qrcode_bgcolor varchar(30) NOT NULL,
                                qrcode_fgcolor varchar(30) NOT NULL,
                                PRIMARY KEY (id));`
			upgradequery[4] = `INSERT INTO qr_code_config
                                (qrcode_bgcolor,qrcode_fgcolor) 
                                VALUES('255;255;255;255','0;0;0;255');`

			err = upgradeSchema(upgradequery)
			if err != nil {
				return 0, err
			}
		}
		fallthrough
	case 1:
		{
			var upgradequery []string = make([]string, 2)
			upgradequery[0] = `CREATE TABLE IF NOT EXISTS oidc_config (
                                id serial NOT NULL,
                                enabled bool DEFAULT false,
                                client_id varchar(64),
                                client_secret varchar(64),
                                discovery_url varchar(255),
                                PRIMARY KEY (id));`
			upgradequery[1] = `UPDATE serverconfig
                                SET schema_version = 2
                                WHERE ID = 1;`

			err = upgradeSchema(upgradequery)
			if err != nil {
				return 1, err
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
		err = transaction.Rollback()
		if err != nil {
			return err
		}
		return errors.New("transaction failed. database was rolled back")
	} else {
		return transaction.Commit()
	}
}
