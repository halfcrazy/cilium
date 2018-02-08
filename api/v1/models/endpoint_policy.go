// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// EndpointPolicy Policy information of an endpoint
// swagger:model EndpointPolicy

type EndpointPolicy struct {

	// List of identities allowed to communicate to this endpoint
	//
	AllowedIngressSecurityIdentities []int64 `json:"allowed-ingress-security-identities"`

	// Build number of calculated policy in use
	Build int64 `json:"build,omitempty"`

	// cidr policy
	CidrPolicy *CIDRPolicy `json:"cidr-policy,omitempty"`

	// Own identity of endpoint
	ID int64 `json:"id,omitempty"`

	// l4
	L4 *L4Policy `json:"l4,omitempty"`
}

/* polymorph EndpointPolicy allowed-ingress-security-identities false */

/* polymorph EndpointPolicy build false */

/* polymorph EndpointPolicy cidr-policy false */

/* polymorph EndpointPolicy id false */

/* polymorph EndpointPolicy l4 false */

// Validate validates this endpoint policy
func (m *EndpointPolicy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAllowedIngressSecurityIdentities(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateCidrPolicy(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateL4(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EndpointPolicy) validateAllowedIngressSecurityIdentities(formats strfmt.Registry) error {

	if swag.IsZero(m.AllowedIngressSecurityIdentities) { // not required
		return nil
	}

	return nil
}

func (m *EndpointPolicy) validateCidrPolicy(formats strfmt.Registry) error {

	if swag.IsZero(m.CidrPolicy) { // not required
		return nil
	}

	if m.CidrPolicy != nil {

		if err := m.CidrPolicy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cidr-policy")
			}
			return err
		}
	}

	return nil
}

func (m *EndpointPolicy) validateL4(formats strfmt.Registry) error {

	if swag.IsZero(m.L4) { // not required
		return nil
	}

	if m.L4 != nil {

		if err := m.L4.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("l4")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EndpointPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EndpointPolicy) UnmarshalBinary(b []byte) error {
	var res EndpointPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
