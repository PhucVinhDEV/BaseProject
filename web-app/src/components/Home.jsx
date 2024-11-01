import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getToken } from "../services/localStorageService";
import Header from "./header/Header";
import { Box, Card, CircularProgress, Typography } from "@mui/material";

export default function Home() {
  const navigate = useNavigate();
  const [userDetails, setUserDetails] = useState({});
  const [roleEnum, setRoleEnum] = useState({});
  const getUserDetails = async (accessToken) => {
    console.log("Access" + accessToken);
    const response = await fetch(
      `http://localhost:8080/api/v1/self`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`, // Add the Bearer token in the Authorization header
        },
      }
    );

    const data = await response.json();
    console.log(data);
    setUserDetails(data);
  };

  useEffect(() => {
    const accessToken = getToken();

    if (!accessToken) {
      navigate("/login");
    }

    getUserDetails(accessToken);
  }, [navigate]);

  return (
    <>
      <Header></Header>
      {userDetails ? (
        <Box
          display="flex"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          height="100vh"
          bgcolor={"#f0f2f5"}
        >
          <Card
            sx={{
              minWidth: 400,
              maxWidth: 500,
              boxShadow: 4,
              borderRadius: 4,
              padding: 4,
            }}
          >
            <Box
              sx={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                width: "100%", // Ensure content takes full width
              }}
            >
              <img
                src={userDetails.picture}
                alt={`${userDetails.given_name}'s profile`}
                className="profile-pic"
              />
              <p>Welcome back to ArtDevs Social,</p>
              <h1 className="name">{userDetails.name}</h1>
              <p className="email">{userDetails.email}</p>{" "}
            </Box>
          </Card>
        </Box>
      ) : (
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            gap: "30px",
            justifyContent: "center",
            alignItems: "center",
            height: "100vh",
          }}
        >
          <CircularProgress></CircularProgress>
          <Typography>Loading ...</Typography>
        </Box>
      )}
    </>
  );
}
