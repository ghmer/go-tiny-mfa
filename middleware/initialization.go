package middleware

import (
	"fmt"
	"log"
	"os"

	"github.com/ghmer/go-tiny-mfa/structs"
	"github.com/ghmer/go-tiny-mfa/utils"
)

//InitializeSystem will initialize the database and the root key
func InitializeSystem() error {
	config, err := initializeDatabase()
	if err != nil {
		return err
	}
	keycreated, err := initializeRootKey()
	if err != nil {
		return err
	}
	err = storeRootTokenToDisk(config)
	if err != nil {
		return err
	}
	printSystemConfiguration(config, keycreated)

	return nil
}

//initializeDatabase will create the issuer and user tables
func initializeDatabase() (structs.ServerConfig, error) {
	err := initializeSystemTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	err = initializeIssuerTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	err = initializeUserTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	err = initializeAuditTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	err = initializeAccessTokenTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	err = initializeQrCodeConfigurationTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}

	err = initializeOidcConfigurationTable()
	if err != nil {
		return structs.ServerConfig{}, err
	}

	config, err := initializeStandardConfiguration()
	if err != nil {
		return structs.ServerConfig{}, err
	}

	return config, nil
}

//initializes the user table in the database
func initializeUserTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS accounts (
        id varchar(45) NOT NULL,
        username varchar(32) NOT NULL,
        email varchar(128) NOT NULL,
        issuer_id varchar(45) NOT NULL,
        key varchar(128) NOT NULL UNIQUE,
        enabled boolean DEFAULT '1',
        unique (username, email, issuer_id),
        PRIMARY KEY (id)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the audit table in the database
func initializeAuditTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS audit (
        id serial NOT NULL,
        issuer varchar(32) NOT NULL,
        username varchar(32) NOT NULL,
        message varchar(16) NOT NULL,
        success boolean DEFAULT '0',
        validated_on timestamp NOT NULL,
        PRIMARY KEY (id)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the issuer table in the database
func initializeIssuerTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS issuer (
        id varchar(45) NOT NULL,
        name varchar(32) NOT NULL UNIQUE,
        contact varchar(255) NOT NULL,
        key varchar(128) NOT NULL UNIQUE,
        token_length smallint NOT NULL,
        enabled boolean DEFAULT '1',
        PRIMARY KEY (id)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the access_token table
func initializeAccessTokenTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS access_tokens (
        id varchar(45) NOT NULL,
        ref_id_issuer varchar(45),
        access_token varchar(64) NOT NULL,
        description varchar(255),
        created_on timestamp NOT NULL,
        last_access_time timestamp,
        PRIMARY KEY (access_token)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the system table in the database
func initializeSystemTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS serverconfig (
        id serial NOT NULL,
        http_port integer NOT NULL,
        deny_limit smallint NOT NULL,
        verify_tokens bool DEFAULT false,
        root_token varchar(64) NOT NULL,
        schema_version smallint NOT NULL,
        PRIMARY KEY (id)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}

	return nil
}

//initializes the access_token table
func initializeQrCodeConfigurationTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS qr_code_config (
        id serial NOT NULL,
        qrcode_bgcolor varchar(30) NOT NULL,
        qrcode_fgcolor varchar(30) NOT NULL,
        PRIMARY KEY (id)
    );`
	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initializes the oidc table
func initializeOidcConfigurationTable() error {
	db, err := CreateConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	createstring := `CREATE TABLE IF NOT EXISTS oidc_config (
        id serial NOT NULL,
        enabled bool DEFAULT false,
        client_id varchar(64),
        client_secret varchar(64),
        discovery_url varchar(255),
        PRIMARY KEY (id)
    );`

	_, err = db.Exec(createstring)
	if err != nil {
		return err
	}
	return nil
}

//initialize standard configuration
func initializeStandardConfiguration() (structs.ServerConfig, error) {
	db, err := CreateConnection()
	if err != nil {
		return structs.ServerConfig{}, err
	}
	defer db.Close()

	var config = structs.StandardServerConfig()
	hashedtoken, err := utils.BcryptHash([]byte(config.RootToken))
	if err != nil {
		return structs.ServerConfig{}, err
	}

	insertQuery := `INSERT INTO serverconfig 
    (http_port,deny_limit,verify_tokens,root_token, schema_version) 
    VALUES($1,$2,$3,$4,$5);`
	_, err = db.Exec(
		insertQuery,
		config.RouterPort,
		config.DenyLimit,
		config.VerifyTokens,
		string(hashedtoken),
		config.SchemaVersion)

	if err != nil {
		return structs.ServerConfig{}, err
	}

	qrcodeconfig := structs.StandardQrCodeConfig()

	insertQuery = `INSERT INTO qr_code_config(qrcode_bgcolor, qrcode_fgcolor) VALUES($1,$2);`
	_, err = db.Exec(
		insertQuery,
		qrcodeconfig.BgColor.ToString(),
		qrcodeconfig.FgColor.ToString())

	if err != nil {
		return structs.ServerConfig{}, err
	}

	return config, nil
}

func printSystemConfiguration(config structs.ServerConfig, addKeyMessage bool) {
	log.Println()
	log.Println("----------------------------------------------------------------")
	log.Println("tiny-mfa configuration")
	log.Println("----------------------------------------------------------------")
	log.Println("router port  ", config.RouterPort)
	log.Println("deny limit   ", config.DenyLimit)
	log.Println("verify tokens", config.VerifyTokens)
	log.Println("root token   ", RootTokenFilePath)
	log.Println("----------------------------------------------------------------")
	if addKeyMessage {
		log.Println("Attention:", "a new root encryption key has been generated.")
		log.Println("It is advised to create a backup as soon as possible.")
		log.Println()
		log.Println("root key location:", SecretFilePath)
		log.Println("----------------------------------------------------------------")
		log.Println()
	}
}

//checks whether the root key exists on the file system
//will create it if this is not the case
func initializeRootKey() (bool, error) {
	var keycreated bool = false
	_, err := os.Stat(SecretFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// key does not exist
			base32RootKey, err := utils.GenerateExtendedKeyBase32()
			if err != nil {
				return keycreated, err
			}
			file, err := os.Create(SecretFilePath)
			if err != nil {
				return keycreated, err
			}

			// Defer is used for purposes of cleanup like
			// closing a running file after the file has
			// been written and main //function has
			// completed execution
			defer file.Close()
			_, err = file.WriteString(base32RootKey)
			if err != nil {
				return keycreated, err
			}
			defer os.Chmod(SecretFilePath, 0400)

			keycreated = true
			return keycreated, err
		}
	}

	return keycreated, err
}

func storeRootTokenToDisk(config structs.ServerConfig) error {
	_, err := os.Stat(RootTokenFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// file does not exist
			file, err := os.Create(RootTokenFilePath)
			if err != nil {
				return err
			}

			// Defer is used for purposes of cleanup like
			// closing a running file after the file has
			// been written and main //function has
			// completed execution
			defer file.Close()
			_, err = file.WriteString(fmt.Sprintf("root-token: %s", config.RootToken))
			if err != nil {
				return err
			}
			defer os.Chmod(RootTokenFilePath, 0400)

			return err
		} else {
			return err
		}
	}

	return nil
}
