package ponPool

type Builder struct {
	BuilderPubkey string `db:"builder_pubkey" json:"id"`
	Status        string `db:"status" json:"status"`
}

type BuilderPool struct {
	Data struct {
		Builders []Builder `json:"builders"`
	} `json:"data"`
}
