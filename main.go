package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	deserializer "github.com/worldcoin/ptau-deserializer/deserialize"
)

func main() {
	app := &cli.App{
		Name:  "ptau-deserialize",
		Usage: "Deserialize .ptau files into gnark's .ph1 format",
		Action: func(*cli.Context) error {
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "convert",
				Aliases: []string{"c"},
				Usage:   "Deserialize .ptau file into .ph1 format and write to `OUTPUT`",
				Action: func(cCtx *cli.Context) error {
					ptauFilePath := cCtx.String("input")
					outputFilePath := cCtx.String("output")

					file, err := deserializer.InitPtau(ptauFilePath)
					if err != nil {
						panic(err)
					}
					err = deserializer.WritePhase1FromPtauFile(file, outputFilePath)
					if err != nil {
						panic(err)
					}

					// ptau, err := deserializer.ReadPtau(ptauFilePath)

					//if err != nil {
					//	return err
					//}
					//
					//phase1, err := deserializer.ConvertPtauToPhase1(ptau)
					//
					//if err != nil {
					//	return err
					//}
					//
					//// Write phase1 to file
					//err = deserializer.WritePhase1(phase1, uint8(ptau.Header.Power), outputFilePath)
					//
					//if err != nil {
					//	return err
					//}

					return nil
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Usage:    "Load `FILE`.ptau to convert to .ph1",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Usage:    "File output for the phase 1 conversion (`FILE`.ph1)",
						Required: true,
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%s", err)
	}
}
