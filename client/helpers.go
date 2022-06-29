package client

import "io/ioutil"

func WriteData(filename string, data []byte) error {
	err := ioutil.WriteFile(filename, data, 0600)
	return err
}
