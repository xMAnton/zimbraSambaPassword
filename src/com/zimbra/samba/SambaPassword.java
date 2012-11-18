/*
   Copyright 2012 Antonio Messina (a.messina@iknowconsulting.it)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. 
*/

package com.zimbra.samba;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.ldap.ChangePasswordListener;
import com.zimbra.cs.extension.ZimbraExtension;

public class SambaPassword implements ZimbraExtension {
    public SambaPassword() {
    }
			
    @Override
    public void init() throws ServiceException {
        ChangePasswordListener.register("SambaPassword", new SambaChangePasswordListener());
    }

    @Override
    public void destroy() {
    }

    @Override
    public String getName() {
        return "SambaPassword";
    }
}
