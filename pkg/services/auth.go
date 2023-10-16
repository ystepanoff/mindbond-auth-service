package services

import (
	"context"
	"net/http"

	"flotta-home/mindbond/auth-service/pkg/db"
	"flotta-home/mindbond/auth-service/pkg/models"
	"flotta-home/mindbond/auth-service/pkg/pb"
	"flotta-home/mindbond/auth-service/pkg/utils"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.RegisterResponse{
			Status: http.StatusConflict,
			Error:  "E-Mail already exists",
		}, nil
	}

	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)
	user.Language = req.Language
	user.Handle = req.Handle

	s.H.DB.Create(&user)

	return &pb.RegisterResponse{
		Status: http.StatusCreated,
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)

	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	token, _ := s.Jwt.GenerateToken(user)

	return &pb.LoginResponse{
		Status: http.StatusOK,
		UserId: user.Id,
		Handle: user.Handle,
		Token:  token,
	}, nil
}

func (s *Server) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Id: req.UserId, Token: req.Token}).First(&user); result.Error != nil {
		return &pb.LogoutResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	user.Token = ""
	s.H.DB.Save(&user)

	return &pb.LogoutResponse{}, nil
}

func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)

	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, nil
	}

	var user models.User

	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: user.Id,
		Handle: user.Handle,
	}, nil
}
