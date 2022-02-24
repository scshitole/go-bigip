package main

import (
	"fmt"
"github.com/scshitole/go-bigip"

)

func main() {
  //scanner := bufio.NewScanner(os.Stdin)
 //	var Bigipmgmt, Port, User, Pass string
 	fmt.Print("Enter your BIG-IP Management IP: ")
 	//fmt.Print("Enter your BIG-IP Management IP: ")
 	/*scanner.Scan()
 	Bigipmgmt = scanner.Text()
  fmt.Print("Enter your BIG-IP Management IP Port: ")
 	//fmt.Print("Enter your BIG-IP Management IP: ")
 	scanner.Scan()
 	Port = scanner.Text()
 	fmt.Print("Enter your Username: ")
 	scanner.Scan()
 	User = scanner.Text()
 	fmt.Print("Enter your Password: ")
 	scanner.Scan()
 	Pass = scanner.Text()
 	fmt.Println("Attempting to Connect...\n")
	*/fmt.Println("Attempting to connect...")
	// Establish our session to the BIG-IP
f5 := bigip.NewSession("ip_address", "443", "admin", "password", nil)
// Iterate over all the virtual servers, and display their names.
	vservers, err := f5.VirtualServers()
	if err != nil {
		panic(err.Error())
	}

	for _, vs := range vservers.VirtualServers {
		fmt.Printf("Name: %s\n %s\n", vs.Name, vs.Pool)
		//vs.Description = "Modified Sanjay Shitole"
		//	f5.ModifyVirtualServer(vs.Name, &vs)
		//fmt.Printf(" value of vs ......\n ", vs )
	}
	wafpolicy, err := f5.WAFpolicies()
	if err != nil {
		panic(err.Error())
	}


	for _, waf := range wafpolicy.WAFpolicies {
  //  fmt.Printf("Kind: %v\n", waf)
		fmt.Printf("Policy ID is : %v\n\n", waf.PolicyID)
    name := waf.PolicyID
  readWafPolicy, err := f5.Readpolicyparameters(name)
  if err != nil {
    panic(err.Error())
    fmt.Printf("here is the dump ", readWafPolicy)
  }

  fmt.Printf("Policy name is ---> %s <---- Policy reference parameters %s\n\n \n\n", waf.Name, waf.ParameterReference)

readfiletype, err := f5.Readfiletypes(name)
if err != nil {
  panic(err.Error())
  fmt.Printf("here is the dump ", readfiletype)
}
fmt.Printf("Policy name is ---> %s <---- Policy reference parameters %s\n\n \n\n", waf.Name, readfiletype)
}
}

/*func findWAFID(Bigipmgmt, Port, User, Pass string) bool {
  fmt.Println("Checking UDP iRules exists on BIG-IP ......\n")
  	// Iterate over all the iRules, and display their names.
  	f5 := bigip.NewSession(Bigipmgmt, Port, User, Pass, nil)

  	irules, err := f5.IRules()
  	if err != nil {
  		panic(err.Error())
  	}
    for _, irule := range irules.IRules {
    		//	fmt.Printf("Name:  %s\n", irule.Name)
    		//vs.Description = "Modified Sanjay Shitole"

    		if irule.Name == "Tetration_UDP_L4_ipfix" {
    			return true
    		}

    	}
  return false
}*/
