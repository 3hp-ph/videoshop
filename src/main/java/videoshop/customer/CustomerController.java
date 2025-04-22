/*
 * Copyright 2013-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package videoshop.customer;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties.Authentication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
class CustomerController {

	private static final Logger LOG = LoggerFactory.getLogger(CustomerDataInitializer.class);
	private final CustomerManagement customerManagement;

	CustomerController(CustomerManagement customerManagement) {

		Assert.notNull(customerManagement, "CustomerManagement must not be null!");

		this.customerManagement = customerManagement;
	}

	// (｡◕‿◕｡)
	// Über @Valid können wir die Eingaben automagisch prüfen lassen, ob es Fehler gab steht im BindingResult,
	// dies muss direkt nach dem @Valid Parameter folgen.
	// Siehe außerdem videoshop.model.validation.RegistrationForm
	// Lektüre: http://docs.spring.io/spring/docs/current/spring-framework-reference/html/validation.html
	@PostMapping("/register")
	String registerNew(@Valid RegistrationForm form, Errors result) {

		if (result.hasErrors()) {
			return "register";
		}

		// (｡◕‿◕｡)
		// Falls alles in Ordnung ist legen wir einen Customer an
		customerManagement.createCustomer(form);

		return "redirect:/";
	}

	@GetMapping("/register")
	String register(Model model, RegistrationForm form) {
		return "register";
	}

	@PostMapping("/change")
	@PreAuthorize("hasRole('CUSTOMER')")
	String change(@Valid RegistrationForm form, Errors result) {
		//Assert.isTrue(form.isChange(), "RegistrationForm must be a change form!");

		if (result.hasFieldErrors("username") || result.hasFieldErrors("address") || result.hasFieldErrors("email")) {
			return "change";
		}
		Customer c = getCustomer();
		c.getUserAccount().setUsername(form.getName());
		c.setAddress(form.getAddress());
		c.setEmail(form.getEmail());
		customerManagement.saveCustomer(c);
		return "redirect:/";
	}

	@GetMapping("/change")
	@PreAuthorize("hasRole('CUSTOMER')")
	String change(Model model, RegistrationForm form) {
		return "change";
	}

	@GetMapping("/customers")
	@PreAuthorize("hasRole('BOSS')")
	String customers(Model model) {

		model.addAttribute("customerList", customerManagement.findAll());

		return "customers";
	}

	@GetMapping("/profile")
	@PreAuthorize("hasRole('CUSTOMER')")
	String showProfile(Model model, Authentication authentication) {
		
		/*SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username = userDetails.getUsername();
		LOG.info("current User: "  + username);
		Streamable<Customer> allCustomers = customerManagement.findAll();
		Customer customer = null;
		for (Customer c : allCustomers) {
			String cUsername = c.getUserAccount().getUsername();
			if (cUsername.equals(username)) {
				customer = c;
				break;
			}
		}*/
		Customer customer = getCustomer();
		if (customer == null) {
			LOG.error("Customer not found for current user.");
			return "redirect:/";			
		}
		model.addAttribute("email", customer.getEmail());
		model.addAttribute("address", customer.getAddress());
		return "profile";
	}

	private Customer getCustomer() {
		UserDetails details = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		//UserAccountIdentifier uid = (UserAccountIdentifier) details;
		Customer customer = null;
		for (Customer c : customerManagement.findAll()) {
			if (c.getUserAccount().getUsername().equals(details.getUsername())) {
				customer = c;
				break;
			}
		}
		return customer;
		//c.getUserAccount().getId() == acc.getId()
	}
}