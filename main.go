package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/zhang19523zhao/wechatUrl/utils"
)

func main() {
	r := gin.Default()

	token := utils.LoadConfig().Token
	receiverId := utils.LoadConfig().ReceiverId
	encodingAeskey := utils.LoadConfig().EncodingAeskey

	r.GET("/wechat/check", func(c *gin.Context) {
		fmt.Println(c.Request.Body)
		vMsgSign := c.Query("msg_signature")
		vTimestamp := c.Query("timestamp")
		vNonce := c.Query("nonce")
		vEchoStr := c.Query("echostr")
		fmt.Printf("msg_signature: %s, timestamp: %s, nonce: %s, echoStr: %s\n", vMsgSign, vTimestamp, vNonce, vEchoStr)

		wxcpt := utils.NewWXBizMsgCrypt(token, encodingAeskey, receiverId, utils.XmlType)
		echoStr, cryptErr := wxcpt.VerifyURL(vMsgSign, vTimestamp, vNonce, vEchoStr, token)
		if nil != cryptErr {
			fmt.Println("verifyUrl fail", cryptErr)
		}
		fmt.Println("verifyUrl success echoStr", string(echoStr))

		c.Writer.WriteString(string(echoStr))
	})
	r.Run(fmt.Sprintf(":%d", utils.LoadConfig().Port))
}
