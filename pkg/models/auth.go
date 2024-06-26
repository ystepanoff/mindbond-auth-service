package models

type User struct {
	Id       int64  `json:"id" gorm:"primaryKey"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Language string `json:"language"`
	Handle   string `json:"handle"`
	Token    string `json:"token"`
	Active   bool   `json:"active" gorm:"default:false"`
}
