package domain

type PrimaryTableEntity struct {
	Id     int    `json:"id" binding:"required"`
	Text   string `json:"text" binding:"required"`
	Number int    `json:"number" binding:"required"`
}
