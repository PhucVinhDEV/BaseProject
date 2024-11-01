import {
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Divider,
  MenuItem,
  Select,
  TextField,
  Typography,
} from "@mui/material";
import GoogleIcon from "@mui/icons-material/Google";
import GitHubIcon from "@mui/icons-material/GitHub";
import { OAuthConfig } from "../configurations/configuration";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getToken, setToken } from "../services/localStorageService";

export default function Login() {
  const navigate = useNavigate();
  const [role, setRole] = useState("");
  const handleClickGoogle = () => {
    const callbackUrl = OAuthConfig.redirectUri;
    const authUrl = OAuthConfig.authUri;
    const googleClientId = OAuthConfig.clientId;

    //Redirect to Google form auth
    const targetUrl = `${authUrl}?redirect_uri=${encodeURIComponent(
      callbackUrl
    )}&response_type=code&client_id=${googleClientId}&scope=openid%20email%20profile`;

    console.log(targetUrl);
    localStorage.setItem("role", role);

    window.location.href = targetUrl;
  };
  const handleRoleChange = (event) => {
    setRole(event.target.value);
  };
  const handleClickLogin = async () => {
    console.log("username", username, password);
    console.log(JSON.stringify({ username, password }));
    const responseLogin = await fetch(
      "http://localhost:8080/api/v1/auth/sign-in",

      {
        method: "POST",
        headers: {
          "Content-Type": "application/json", // Specify JSON content type
        },
        body: JSON.stringify({ username, password }),
      }
    );
    const data = await responseLogin.json();
    if (data.status == 1000) {
      console.log(data);
      setToken(data.result.token);
      navigate("/");
    } else {
      alert("Login failed");
    }
  };

  const handleClickGitHub = () => {
    alert("GitHub");
  };

  useEffect(() => {
    const accessToken = getToken();

    if (accessToken) {
      navigate("/");
    }
  }, [navigate]);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (event) => {
    event.preventDefault();
    // Handle form submission
    console.log("Username:", username);
    console.log("Password:", password);
  };

  return (
    <>
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
            minWidth: 250,
            maxWidth: 400,
            boxShadow: 4,
            borderRadius: 4,
            padding: 4,
          }}
        >
          <CardContent>
            <Typography variant="h5" component="h1" gutterBottom>
              Welcome to ArtDevs Social
            </Typography>
            <Box component="form" onSubmit={handleClickGoogle} sx={{ mt: 2 }}>
              <TextField
                label="Username"
                variant="outlined"
                fullWidth
                margin="normal"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
              <TextField
                label="Password"
                type="password"
                variant="outlined"
                fullWidth
                margin="normal"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
                       {/* Thêm phần chọn Role */}
                       <Select
              fullWidth
              value={role}
              onChange={handleRoleChange}
              displayEmpty
              sx={{ mt: 2, mb: 2 }}
            >
              <MenuItem value="" disabled>
                Select Role
              </MenuItem>
              <MenuItem value="ROLE_EMPLOYER">Employer</MenuItem>
              <MenuItem value="ROLE_ADMIN">Admin</MenuItem>
              <MenuItem value="ROLE_USER">User</MenuItem>
            </Select>
            </Box>
      

          </CardContent>
          <CardActions>
            <Box display="flex" flexDirection="column" width="100%" gap="25px">
              <Button
                type="button"
                variant="contained"
                color="secondary"
                size="large"
                onClick={handleClickLogin}
                fullWidth
                sx={{
                  gap: "10px",
                  backgroundColor: "#4285F4",
                  color: "#FFFFFF",
                  "&:hover": {
                    backgroundColor: "#357AE8",
                  },
                }}
              >
                Login
              </Button>
              <Button
                type="button"
                variant="contained"
                color="secondary"
                size="large"
                onClick={handleClickGoogle}
                fullWidth
                sx={{ gap: "10px" }}
              >
                <GoogleIcon />
                Continue with Google
              </Button>
              <Button
                type="button"
                variant="contained"
                color="secondary"
                size="large"
                onClick={handleClickGitHub}
                fullWidth
                sx={{
                  gap: "10px",
                  backgroundColor: "#333333",
                  color: "#FFFFFF",
                  "&:hover": {
                    backgroundColor: "#242424",
                  },
                }}
              >
                <GitHubIcon />
                Continue with Github
              </Button>
              <Divider></Divider>
              <Button
                type="submit"
                variant="contained"
                color="success"
                size="large"
              >
                Create an account
              </Button>
            </Box>
          </CardActions>
        </Card>
      </Box>
    </>
  );
}
