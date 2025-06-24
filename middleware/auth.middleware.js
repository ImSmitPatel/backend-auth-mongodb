import jwt from "jsonwebtoken"

export const isLoggedIn = async (req, res, next) => {
    try {
        console.log(req.cookies);
        let token = req.cookies?.token

        console.log("Token Found: ", token ? "Yes" : "No")

        if (!token) {
            console.log("NO Token Found")
            return res.status(401).json({
                status: false,
                message: "Authentication Failed"
            })
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        console.log("Decoded token", decoded)
        req.user = decoded
        
        next();

    } catch (error) {
        console.log('Auth Middleware Failure')
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        })
    }


    // next();
}